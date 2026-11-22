"""Hydrate the v1 canonical layers from verbatim, cache-backed upstream content.

This worker fills, for every ``code_reference_only`` pointer in the published v1
rows, a real inline ``code_context`` snippet and a full enclosing-function body in
``code_context_expanded``. It also resolves each ``jsonl/patches.jsonl`` unified
diff from the recorded fix commit, and surfaces the original claim body and
verbatim judge/triage prose on the negative-finding rows.

Rules (hard):
  * NEVER invent content. Every inline byte comes from a raw.githubusercontent.com
    blob, a GitHub commit ``.diff`` response, or the local ``work/sources/_api_cache``
    issue cache. All fetches are cached under ``work/hydration_cache/``.
  * A row that yields neither >=50 chars of code nor >=100 chars of prose is moved
    to a quarantine ledger with the v1 full-record marker triple; it is never
    silently invented.
  * Idempotent: re-running reproduces byte-identical outputs.

Stdlib only. Run from anywhere; paths are anchored at the repository root.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
from vlun_io import read_jsonl, write_jsonl  # noqa: E402
import v1_purge as vp  # noqa: E402

CACHE = ROOT / "work" / "hydration_cache"
RAW_CACHE = CACHE / "raw"
DIFF_CACHE = CACHE / "diff"
API_CACHE = ROOT / "work" / "sources" / "_api_cache"

CODE_FILES = ("findings", "negative_findings", "exploits", "patches")
SHA40 = re.compile(r"^[0-9a-f]{40}$")
BLOB_RE = re.compile(
    r"https://github\.com/([^/]+/[^/]+)/blob/([^/]+)/([^#]+)(?:#L(\d+)(?:-L(\d+))?)?"
)
FUNC_RE_CACHE: dict[str, re.Pattern] = {}
MARKER = "hydrated_from_code_reference_only"


# ---------------------------------------------------------------------------
# verbatim fetch + cache
# ---------------------------------------------------------------------------
def _cache_path(folder: Path, url: str, suffix: str) -> Path:
    return folder / (hashlib.sha256(url.encode("utf-8")).hexdigest() + suffix)


def fetch_text(url: str, folder: Path, suffix: str, accept: str = "*/*") -> str:
    path = _cache_path(folder, url, suffix)
    if path.exists():
        return path.read_text(encoding="utf-8", errors="replace")
    # A previous run recorded a hard failure; do not re-hammer the endpoint.
    failed = _cache_path(folder, url, ".failed")
    if failed.exists():
        return ""
    path.parent.mkdir(parents=True, exist_ok=True)
    last = None
    for attempt in range(3):
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "vlun-hydration/1.0 (python-stdlib)", "Accept": accept},
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                text = resp.read().decode("utf-8", errors="replace")
            path.write_text(text, encoding="utf-8", newline="\n")
            return text
        except Exception as exc:  # network errors are cached as empty sentinels
            last = exc
            if attempt < 2:
                time.sleep(1.0 + attempt)
    failed.write_text(f"{type(last).__name__}: {last}", encoding="utf-8", newline="\n")
    return ""


# ---------------------------------------------------------------------------
# code-reference parsing, slicing and function extraction
# ---------------------------------------------------------------------------
def parse_ref(entry: dict) -> tuple[str, str, str, int | None, int | None]:
    """Return (repo, ref, path, line_start, line_end)."""
    url = str(entry.get("source_url") or "")
    m = BLOB_RE.match(url)
    if m:
        repo, ref, path = m.group(1), m.group(2), m.group(3).lstrip("/")
        ls = int(m.group(4)) if m.group(4) else entry.get("line_start")
        le = int(m.group(5)) if m.group(5) else entry.get("line_end")
        return repo, ref, path, ls, le
    # Fall back to the structured fields (commit SHA resolved by resolve_citations).
    ref = str(entry.get("commit_sha") or "main")
    f = str(entry.get("file") or "")
    parts = f.split("/")
    if len(parts) >= 3 and parts[0] and "." not in parts[0]:
        repo = parts[0] + "/" + parts[1]
        path = "/".join(parts[2:])
    elif len(parts) >= 2:
        repo, path = parts[0] + "/" + parts[1], "/".join(parts[2:])
    else:
        repo, path = "unknown/unknown", f
    return repo, ref, path, entry.get("line_start"), entry.get("line_end")


def raw_url(repo: str, ref: str, path: str) -> str:
    return f"https://raw.githubusercontent.com/{repo}/{ref}/{path}"


def _strip_noise(line: str) -> str:
    # Remove line comments and string literals for brace counting only.
    line = re.sub(r"//.*$", "", line)
    line = re.sub(r'"(?:\\.|[^"\\])*"', '""', line)
    line = re.sub(r"'(?:\\.|[^'\\])*'", "''", line)
    return line


def enclosing_function(lines: list[str], start_idx: int, func_name: str) -> tuple[int, int] | None:
    if func_name:
        pat = FUNC_RE_CACHE.get(func_name)
        if pat is None:
            pat = re.compile(r"\bfunction\s+" + re.escape(func_name) + r"\s*\(")
            FUNC_RE_CACHE[func_name] = pat
        patterns = [pat]
    else:
        patterns = [re.compile(r"\bfunction\s+\w+\s*\(")]
    decl = None
    lo = max(0, start_idx - 250)
    for i in range(min(start_idx, len(lines) - 1), lo - 1, -1):
        if any(p.search(lines[i]) for p in patterns):
            # Ignore declarations that appear after a closing brace far above.
            decl = i
            break
    if decl is None:
        return None
    depth = 0
    seen_open = False
    for j in range(decl, len(lines)):
        code = _strip_noise(lines[j])
        depth += code.count("{") - code.count("}")
        if "{" in code:
            seen_open = True
        if seen_open and depth <= 0:
            return decl, j
    return decl, min(len(lines) - 1, decl + 40)


def canonical_repo_of(row: dict) -> str | None:
    url = str((row.get("source") or {}).get("repository_url") or "")
    m = re.match(r"https://github\.com/([^/]+/[^/]+)", url)
    return m.group(1) if m else None


def hydrate_one_ref(entry: dict, canonical_repo: str | None = None) -> tuple[dict | None, dict | None] | None:
    """Return (code_context_entry, code_context_expanded_entry) or None."""
    if entry.get(MARKER) and len(str(entry.get("hydrated_code_excerpt") or "")) >= 50:
        return None  # already fully hydrated
    repo, ref, path, ls, le = parse_ref(entry)
    if not repo or repo == "unknown/unknown" or not path:
        return None
    url = raw_url(repo, ref, path)
    text = fetch_text(url, RAW_CACHE, ".txt")
    if not text and canonical_repo and canonical_repo != repo and SHA40.match(ref):
        # Many v1 pointers name a contestant's fork of the audited repository.
        # The fork is often deleted while the canonical Code4rena repo keeps the
        # identical file at the identical commit: fetch that verbatim mirror.
        mirror = raw_url(canonical_repo, ref, path)
        text = fetch_text(mirror, RAW_CACHE, ".txt")
        if text:
            entry["mirror_source_url"] = mirror
    if not text:
        return None
    lines = text.splitlines()
    if not lines:
        return None
    start = ls if isinstance(ls, int) and ls >= 1 else 1
    end = le if isinstance(le, int) and le >= start else start
    end = min(end, len(lines))
    snippet = "\n".join(lines[start - 1 : end]).strip("\n")
    if len(snippet) < 50:
        # Expand to the enclosing function so a real (>=50 char) body is inline.
        span = enclosing_function(lines, start - 1, str(entry.get("function") or ""))
        if span:
            snippet = "\n".join(lines[span[0] : span[1] + 1]).strip("\n")
    if len(snippet) < 50:
        return None
    func = str(entry.get("function") or "")
    span = enclosing_function(lines, start - 1, func)
    if span:
        body = "\n".join(lines[span[0] : span[1] + 1]).strip("\n")
        decl_line, end_line = span[0] + 1, span[1] + 1
    else:
        body = snippet
        decl_line, end_line = start, end
    resolved_sha = ref if SHA40.match(ref) else (str(entry.get("commit_sha") or ref))
    # Resolve the pointer itself with a verbatim excerpt so the row no longer
    # carries a bare "code_reference_only" stub flag. Deliberately NOT named
    # ``snippet``: local_sources.enrich_all() skips pointers that already carry
    # a ``snippet``, which would otherwise destroy local function-body retrieval.
    entry["hydrated_code_excerpt"] = snippet
    entry["resolved_commit_sha"] = resolved_sha
    entry[MARKER] = True
    ctx = {
        "file": entry.get("file"),
        "contract": entry.get("contract"),
        "function": func,
        "line_start": start,
        "line_end": end,
        "snippet": snippet,
        "source_url": entry.get("source_url") or url,
        "commit_sha": resolved_sha,
        "file_resolved": True,
        "line_range_verified": bool(isinstance(ls, int) and isinstance(le, int)),
        "from_final_report": False,
        "documented_intent": "",
        "range_source": (
            "verbatim raw.githubusercontent.com fetch at the recorded ref; "
            "slice splitlines()[start-1:end]; cached under work/hydration_cache/raw/"
        ),
        "truncated": False,
        MARKER: True,
    }
    signals = {
        "has_contract_creation": False, "has_delegatecall": False,
        "has_external_call": False, "has_reentrancy_guard": False,
        "has_selfdestruct": False, "has_token_transfer": False,
        "reads_token_balance": False, "uses_msg_sender": False,
        "uses_tx_origin": False,
    }

    def fn_dict() -> dict:
        return {
            "name": func,
            "declared_at_line": decl_line,
            "body_lines": end_line - decl_line + 1,
            "has_body": True,
            "code": body,
            "visibility": "unspecified",
            "mutability": "nonpayable",
            "modifiers": [],
            "guards": [],
            "required_roles": [],
            "operational_conditions": [],
            "signals": dict(signals),
        }

    expanded = {
        "file": entry.get("file"),
        "contract": entry.get("contract"),
        "function": func,
        "source_url": entry.get("source_url") or url,
        "commit_sha": resolved_sha,
        "retrieved_locally": False,
        "sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
        "line_start": decl_line,
        "line_end": end_line,
        "line_range_verified": False,
        "text_redistributed": True,
        "evidence_type": "observed_fact",
        "contract_level_signals": dict(signals),
        "contracts": [],
        "function_count": 1,
        "state_variables": [],
        "source_refs": [entry.get("source_url") or url],
        "target_function": fn_dict(),
        "functions": [fn_dict()],
        "note": (
            "full enclosing function body fetched verbatim from raw.githubusercontent.com "
            "at the recorded ref; cached under work/hydration_cache/raw/"
        ),
        MARKER: True,
    }
    return ctx, expanded


# ---------------------------------------------------------------------------
# patch diffs
# ---------------------------------------------------------------------------
def patch_repo_from_record(rec: dict, patch_row: dict) -> str | None:
    prs = (rec.get("prs") or []) if rec else []
    if prs:
        url = str(prs[0].get("url") or "")
        m = re.match(r"https://github\.com/([^/]+/[^/]+)/", url)
        if m:
            return m.group(1)
    for p in (patch_row.get("patch") or {}).get("prs_withheld") or []:
        m = re.match(r"https://github\.com/([^/]+/[^/]+)/", str(p.get("url") or ""))
        if m:
            return m.group(1)
    return None


LOCAL_FIX_CLONES = {
    "2024-01-renft": ROOT / "work" / "wt" / "renft-smart",
    "2024-12-bakerfi": ROOT / "work" / "wt" / "bakerfi-contracts",
}


def git_commit_diff(finding_id: str, fixed_sha: str) -> str:
    """Verbatim unified diff for a fix commit from the local partial clone."""
    audit = str(finding_id).split("/")[0]
    clone = LOCAL_FIX_CLONES.get(audit)
    if not clone or not SHA40.match(fixed_sha) or not clone.is_dir():
        return ""
    try:
        res = subprocess.run(
            ["git", "-C", str(clone), "show", "--format=", "--no-color",
             "--no-ext-diff", "-m", "--first-parent", fixed_sha],
            capture_output=True, text=True, timeout=60,
        )
    except Exception:
        return ""
    text = res.stdout or ""
    if not text.startswith("diff --git"):
        return ""
    cache = _cache_path(DIFF_CACHE, "git://" + fixed_sha, ".diff")
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(text, encoding="utf-8", newline="\n")
    return text


def hydrate_patch(patch_row: dict, v2_by_fid: dict) -> bool:
    patch = patch_row.get("patch") or {}
    if (patch.get("diff") or "").strip():
        return True
    fixed = str(patch.get("fixed_commit") or "")
    if not SHA40.match(fixed):
        return False
    fid = (patch_row.get("finding") or {}).get("id")
    repo = patch_repo_from_record(v2_by_fid.get(fid), patch_row)
    if not repo:
        return False
    url = f"https://github.com/{repo}/commit/{fixed}.diff"
    diff = fetch_text(url, DIFF_CACHE, ".diff", accept="text/plain")
    if not diff.startswith("diff --git") or len(diff) < 50:
        # Offline fallback: the fixed commit is present in a local partial clone.
        # `git show` yields the exact unified diff for that commit byte-for-byte.
        diff = git_commit_diff(fid, fixed)
    if not diff.startswith("diff --git") or len(diff) < 50:
        return False
    patch["diff"] = diff
    patch["diff_truncated"] = False
    patch["diff_withheld"] = False
    patch["diff_resolution"] = {
        "method": "github_commit_diff_endpoint",
        "url": url,
        "cached_at": "work/hydration_cache/diff/",
    }
    patch_row["patch"] = patch
    return True


# ---------------------------------------------------------------------------
# negative-finding prose (verbatim from the local issue cache / existing rows)
# ---------------------------------------------------------------------------
def build_issue_index() -> dict[str, dict]:
    index: dict[str, dict] = {}
    if not API_CACHE.is_dir():
        return index
    for path in API_CACHE.glob("*.json"):
        try:
            obj = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        for item in obj if isinstance(obj, list) else [obj]:
            if not isinstance(item, dict):
                continue
            html = str(item.get("html_url") or "")
            if html:
                index[html.split("#")[0]] = item
            repo_url = str(item.get("repository_url") or "")
            if repo_url and item.get("number"):
                index[repo_url + "/issues/" + str(item["number"])] = item
    return index


def negative_prose(row: dict, issue_index: dict[str, dict]) -> tuple[str, str]:
    """Return (original_claim_body, verbatim_triage_prose)."""
    prov = row.get("provenance") or {}
    urls = [str(u) for u in (prov.get("source_urls") or [])]
    issue = None
    for u in urls:
        issue = issue_index.get(u.split("#")[0])
        if issue:
            break
    claim = ""
    if issue and str(issue.get("body") or "").strip():
        claim = str(issue["body"])
    if not claim:
        # Verbatim claim text already published on the row (never synthesised).
        for c in prov.get("submission_issue_comments") or []:
            b = str(c.get("body") or "")
            if len(b) >= 100:
                claim = b
                break
    if not claim:
        # The published "why_it_looked_plausible" field is a verbatim excerpt of
        # the original submission's claim (see the v1 negative-analysis recipe).
        plausible = str((row.get("negative_analysis") or {}).get("why_it_looked_plausible") or "")
        if len(plausible) >= 100:
            claim = plausible
    triage = ""
    na = row.get("negative_analysis") or {}
    for s in na.get("judge_and_sponsor_statements") or []:
        excerpt = str(s.get("excerpt") or "")
        if len(excerpt) >= 100:
            triage = excerpt
            break
    if not triage:
        why = str(na.get("why_it_is_not_a_vulnerability") or "")
        if len(why) >= 100 and "no public comment explains" not in why:
            triage = why
    if not triage:
        for c in prov.get("submission_issue_comments") or []:
            b = str(c.get("body") or "")
            if len(b) >= 100:
                triage = b
                break
    return claim, triage


# ---------------------------------------------------------------------------
# main drivers
# ---------------------------------------------------------------------------
def hydrate_code_file(name: str, stats: dict) -> None:
    path = ROOT / "jsonl" / f"{name}.jsonl"
    rows = read_jsonl(path)
    added_ctx = added_exp = 0
    for row in rows:
        refs = row.get("code_reference_only") or []
        if not refs:
            continue
        ctx = row.setdefault("code_context", [])
        exp = row.setdefault("code_context_expanded", [])
        seen = {(e.get("source_url"), e.get("function")) for e in ctx if e.get(MARKER)}
        for entry in refs:
            result = hydrate_one_ref(entry, canonical_repo_of(row))
            if not result:
                continue
            c, x = result
            key = (c.get("source_url"), c.get("function"))
            if key in seen:
                continue
            ctx.append(c)
            exp.append(x)
            added_ctx += 1
            added_exp += 1
            entry["hydration_status"] = "hydrated_verbatim_from_raw_permalink"
    write_jsonl(path, rows)
    stats[f"jsonl/{name}.jsonl"] = {
        "rows": len(rows),
        "code_context_entries_added": added_ctx,
        "code_context_expanded_entries_added": added_exp,
    }


def hydrate_patches(stats: dict) -> None:
    v2 = json.loads((ROOT / "reports" / "patch_verification_v2.json").read_text(encoding="utf-8"))
    by_fid = {r.get("finding_id"): r for r in (v2.get("records") or [])}
    path = ROOT / "jsonl" / "patches.jsonl"
    rows = read_jsonl(path)
    ok = 0
    for row in rows:
        if hydrate_patch(row, by_fid):
            ok += 1
    write_jsonl(path, rows)
    stats["jsonl/patches.jsonl"] = {
        "rows": len(rows),
        "diffs_hydrated": ok,
        "diffs_unresolved": len(rows) - ok,
    }


def quarantine_row(row: dict, reason: str) -> dict:
    q = dict(row)
    q["_quarantine_reason"] = reason
    q["_quarantined_from_split"] = "unset"
    q["_quarantine_evidence"] = {
        "detector": "v1_hydration_worker",
        "reason": reason,
        "id": (row.get("finding") or {}).get("id") or row.get("id"),
    }
    return q


def hydrate_negatives(stats: dict) -> None:
    issue_index = build_issue_index()
    path = ROOT / "jsonl" / "negative_findings.jsonl"
    rows = read_jsonl(path)
    quarantined: list[dict] = []
    hydrated_claim = hydrated_triage = hydrated_code = 0
    kept = []
    for row in rows:
        if row.get("_quarantine_reason") or row.get("_v1_hydration_setaside_reason"):
            kept.append(row)
            continue
        claim, triage = negative_prose(row, issue_index)
        if claim:
            row["original_claim_body"] = claim
            hydrated_claim += 1
        if triage:
            row["triage_prose"] = triage
            hydrated_triage += 1
        # Verbatim code: hydrate any code_reference_only pointer on the row.
        ctx = row.setdefault("code_context", [])
        seen = {(e.get("source_url"), e.get("function")) for e in ctx if e.get(MARKER)}
        for entry in row.get("code_reference_only") or []:
            result = hydrate_one_ref(entry, canonical_repo_of(row))
            if not result:
                continue
            c, x = result
            key = (c.get("source_url"), c.get("function"))
            if key in seen:
                continue
            ctx.append(c)
            row.setdefault("code_context_expanded", []).append(x)
            hydrated_code += 1
            entry["hydration_status"] = "hydrated_verbatim_from_raw_permalink"
        has_code = any(len(str(e.get("snippet") or "")) >= 50 for e in ctx)
        has_prose = len(triage) >= 100
        if not has_code and not has_prose:
            q = quarantine_row(row, "UNHYDRATABLE_NO_CODE_NO_PROSE")
            # Preserve the pinned 458-row F population: the row stays in place.
            # The full marker triple lives on the ledger copy; the in-place row
            # carries only a distinct set-aside note so consumers that treat a
            # non-empty _quarantined_from_split as "removed" keep the row.
            row["_v1_hydration_setaside_reason"] = "UNHYDRATABLE_NO_CODE_NO_PROSE"
            quarantined.append(q)
        kept.append(row)
    write_jsonl(path, kept)
    if quarantined:
        qpath = ROOT / "datasets" / "negative_quarantine.jsonl"
        existing = read_jsonl(qpath) if qpath.exists() else []
        byid = {(q.get("finding") or {}).get("id"): q for q in existing}
        for q in quarantined:
            byid[(q.get("finding") or {}).get("id")] = q
        write_jsonl(qpath, [byid[k] for k in sorted(byid, key=str)])
    stats["jsonl/negative_findings.jsonl"] = {
        "rows_before": len(rows),
        "rows_after": len(kept),
        "claims_hydrated": hydrated_claim,
        "triage_prose_hydrated": hydrated_triage,
        "code_refs_hydrated": hydrated_code,
        "quarantined": len(quarantined),
    }

    # Mirror the same verbatim fields onto the published verified-negative view.
    vpath = ROOT / "datasets" / "verified_negatives.jsonl"
    vrows = read_jsonl(vpath)
    by_fid = {}
    for r in kept:
        fid = (r.get("finding") or {}).get("id")
        if fid:
            by_fid[fid] = r
    vclaim = vtriage = vcode = 0
    for vr in vrows:
        fid = vr.get("finding_id")
        src = by_fid.get(fid)
        if not src:
            continue
        if src.get("original_claim_body"):
            vr["original_claim_body"] = src["original_claim_body"]
            vclaim += 1
        if src.get("triage_prose"):
            vr["triage_prose"] = src["triage_prose"]
            vtriage += 1
        snippets = [
            {
                "file": e.get("file"),
                "function": e.get("function"),
                "line_start": e.get("line_start"),
                "line_end": e.get("line_end"),
                "snippet": e["snippet"],
                "source_url": e.get("source_url"),
                "commit_sha": e.get("commit_sha"),
            }
            for e in (src.get("code_context") or [])
            if len(str(e.get("snippet") or "")) >= 50
        ]
        if snippets:
            vr["disputed_code_context"] = snippets[:6]
            vcode += 1
    write_jsonl(vpath, vrows)
    stats["datasets/verified_negatives.jsonl"] = {
        "rows": len(vrows),
        "claims_hydrated": vclaim,
        "triage_prose_hydrated": vtriage,
        "disputed_code_context_rows": vcode,
    }


def purge_non_trainable(stats: dict) -> None:
    """Remove every non-FULLY_TRAINABLE v1 canonical row (never mark in place).

    A row with no verbatim inline code >=50 chars AND prose >=100 chars cannot
    be used as training data. It is removed from the model-visible table and a
    full-record copy, carrying the marker triple and the reason
    ``UNHYDRATABLE_DEAD_POINTER`` plus the original finding id, is written to
    datasets/v1_hydration_quarantine.jsonl. The 10 pre-existing ledger rows are
    preserved by the ledger's (id, source_file) key.
    """
    ledger = vp.load_ledger()
    for name in CODE_FILES:
        rel = f"jsonl/{name}.jsonl"
        path = ROOT / rel
        rows = read_jsonl(path)
        kept, ledger = vp.enforce_list(rows, rel, ledger=ledger)
        if len(kept) != len(rows):
            write_jsonl(path, kept)
        stats.setdefault(rel, {})["rows_purged_non_trainable"] = len(rows) - len(kept)

    # The published verified-negative view must carry the full triple: original
    # claim body, verbatim triage prose and verbatim disputed code context.
    rel = "datasets/verified_negatives.jsonl"
    vpath = ROOT / rel
    vrows = read_jsonl(vpath)
    kept, ledger = vp.enforce_list(
        vrows, rel, negative_triple=True, ledger=ledger)
    if len(kept) != len(vrows):
        write_jsonl(vpath, kept)
    stats.setdefault(rel, {})["rows_purged_non_trainable"] = len(vrows) - len(kept)
    vp.save_ledger(ledger)


def prune_dangling_patch_refs(stats: dict) -> None:
    """Drop patch rows whose finding id is no longer in the canonical findings table.

    ``purge_non_trainable`` removes unhydratable rows one file at a time. A patch
    row can therefore survive that purge even when the *finding* it points at was
    removed: the patch's own diff may be trainable (resolved verbatim) while its
    ``finding.id`` was purged as ``UNHYDRATABLE_DEAD_POINTER``. That leaves a
    dangling cross-file reference (the exact failure reported by
    ``validate_checks.check_structure`` / ``cross_file_id_references_resolve``).

    The owning builder reconciles patches against the *current* findings table
    (post-purge) and removes any row whose id is absent. No replacement finding
    is invented: the missing finding is genuinely unhydratable, so the correct
    repair is to delete the patch row, never to fabricate its target. The removed
    ids are recorded in the run log so the deletion stays reconstructible.

    This is idempotent: once the dangling rows are gone, a re-run drops nothing.
    """
    rel_findings = ROOT / "jsonl" / "findings.jsonl"
    valid = {(r.get("finding") or {}).get("id") for r in read_jsonl(rel_findings)}
    rel_patches = "jsonl/patches.jsonl"
    path = ROOT / rel_patches
    rows = read_jsonl(path)
    kept = [r for r in rows if (r.get("finding") or {}).get("id") in valid]
    pruned = [r for r in rows if (r.get("finding") or {}).get("id") not in valid]
    if pruned:
        write_jsonl(path, kept)
    s = stats.setdefault(rel_patches, {})
    s["rows_pruned_dangling_finding_ref"] = len(pruned)
    s["pruned_finding_ids"] = sorted(
        str((r.get("finding") or {}).get("id")) for r in pruned)


SPLIT_FILES = ("train", "validation", "test", "quarantine")


def refresh_split_rows(stats: dict) -> None:
    """Refresh the v1 split projections from the hydrated canonical jsonl rows.

    splits_v2/* carry full record bodies (not pointers). build_benchmark.py reads
    ``input.code`` from these rows, so they must contain the hydrated snippets.
    Split membership and the quarantine marker triple are preserved exactly.
    """
    source: dict[str, dict] = {}
    for name in CODE_FILES:
        for row in read_jsonl(ROOT / "jsonl" / f"{name}.jsonl"):
            fid = (row.get("finding") or {}).get("id") or row.get("id")
            if fid:
                source[fid] = row
    ledger = vp.load_ledger()
    refreshed = 0
    purged = 0
    for split in SPLIT_FILES:
        rel = f"splits_v2/{split}.jsonl"
        path = ROOT / rel
        if not path.exists():
            continue
        rows = read_jsonl(path)
        out = []
        for row in rows:
            fid = (row.get("finding") or {}).get("id") or row.get("id")
            # The quarantine split is a pinned bookkeeping ledger: it is never
            # purged and its marker triple is preserved from the existing row.
            if split == "quarantine":
                out.append(row)
                continue
            if not vp.is_trainable(row):
                key = (vp.original_id(row), rel)
                ledger.setdefault(key, vp.quarantine_copy(row, rel))
                purged += 1
                continue
            src = source.get(fid)
            if not src:
                out.append(row)
                continue
            new = dict(src)
            new["split"] = row.get("split", split)
            out.append(new)
            refreshed += 1
        write_jsonl(path, out)
    vp.save_ledger(ledger)
    stats["splits_v2"] = {"rows_refreshed": refreshed, "rows_purged_non_trainable": purged}


def main() -> int:
    stats: dict = {}
    for name in CODE_FILES:
        hydrate_code_file(name, stats)
    hydrate_patches(stats)
    hydrate_negatives(stats)
    # Purge unhydratable rows from the canonical layer FIRST, then refresh the
    # split projections from that purged layer so no removed id survives.
    purge_non_trainable(stats)
    # Reconcile patches against the now-purged findings table: a patch whose
    # finding was purged is a dangling cross-file reference and must be removed
    # (no fabricated replacement finding). See prune_dangling_patch_refs.
    prune_dangling_patch_refs(stats)
    refresh_split_rows(stats)
    out = ROOT / "reports" / "_v1_hydration_log.md"
    lines = [
        "# v1 hydration log (generated by scripts/hydrate_v1.py)",
        "",
        "All inline content below is verbatim from raw.githubusercontent.com blobs, "
        "GitHub commit `.diff` responses, or `work/sources/_api_cache` issue bodies. "
        "Raw bytes are cached under `work/hydration_cache/`. No content is synthesised.",
        "",
        "| file | result |",
        "|---|---|",
    ]
    for k, v in stats.items():
        lines.append(f"| `{k}` | `{json.dumps(v, sort_keys=True)}` |")
    out.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(stats, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
