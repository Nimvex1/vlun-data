"""formal.py — Wave-1 adapter for formal / invariant suites (source #6).

Governance (locked, see 00_governance/source_registry.jsonl, source_id
"formal_specs"): METADATA_ONLY.  We store rule id, a SHORT property statement
(<=300 chars), the pinned commit SHA, the file path and an OBSERVED verdict
flag for the governed repos.  No full prose is copied into wave1/.

Strict admission (Bug C fix)
---------------------------
Only genuine named formal properties are admitted:
  (a) CVL ``rule <Name>`` / ``invariant <Name>`` declarations in .spec/.cvl
      files, and
  (b) named invariant/property functions ``invariant_*`` / ``echidna_*`` /
      ``halmos_*`` / ``medusa_*``.

Generic Foundry ``test_*`` functions, test setup helpers (``setUp``,
``constructor``), bare ``assert``/``require`` lines, and rule/invariant-like
tokens in prose files are recorded as candidates but EXCLUDED with an exact
reason.  Nothing is admitted merely because it matched a syntax keyword.

Honest quality (Bug C fix)
--------------------------
``quality.invariants == "high"`` is set ONLY when the row is paired with a
concrete violated/held property or a mutant/vulnerable-vs-clean pair actually
observed in the pinned clone (a committed Certora Prover result matrix), and
the row then carries ``pair_evidence``.  Declaration-only rows are
``unverified`` / ``observed_declaration_unverified``.  No verdict is invented;
``verdict_flag`` is empty unless a concrete Original verdict was observed.

Benchmark redesign (Bug C fix)
------------------------------
``benchmark_wave1/invariants.jsonl`` is REWRITTEN (never appended) from the
paired rows only, with labels strictly from the governed ``formal_property``
domain {property_violated, property_held}.  ``answer`` is the observed verdict
string ("SUCCESS"/"FAIL"), never a fabricated pass/fail.

Outputs (all inside wave1/, single-writer enforced by _common):
  03_candidates/formal_specs/rules.jsonl      every match, incl. dropped
  04_admitted/formal_specs/findings.jsonl     deduplicated admitted metadata
  01_dedup/overlap_manifest.jsonl             append-only overlap evidence
  benchmark_wave1/invariants.jsonl            rewritten paired benchmark tasks
  reports_wave1/formal_harvest.json           run report

Stdlib only.  Clones live in the git-ignored work/sources/ tree.
"""
from __future__ import annotations

import csv
import json
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

# _common.py lives in wave1/scripts/; this file is in wave1/scripts/adapters/.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from _common import (  # noqa: E402
    WAVE1,
    guard_scratch,
    guard_wave1,
    append_jsonl,
    check_keys,
    git_clone,
    ids_from_text,
    load_registry,
    norm_repo_slug,
    read_jsonl,
    sha256_text,
    utc_now,
    write_json,
    write_jsonl,
)

# ---------------------------------------------------------------------------
# configuration
# ---------------------------------------------------------------------------
SOURCE = "formal_specs"

CANDIDATES = WAVE1 / "03_candidates" / "formal_specs" / "rules.jsonl"
ADMITTED = WAVE1 / "04_admitted" / "formal_specs" / "findings.jsonl"
OVERLAP = WAVE1 / "01_dedup" / "overlap_manifest.jsonl"
INVARIANTS = WAVE1 / "benchmark_wave1" / "invariants.jsonl"
REPORT = WAVE1 / "reports_wave1" / "formal_harvest.json"
SOURCE_REGISTRY = WAVE1 / "00_governance" / "source_registry.jsonl"

# Fallback only if the governance file is unreadable; the registry is source of
# truth otherwise.
FALLBACK_REPOS = [
    "Recon-Fuzz/audits",
    "Certora/gho-competition",
    "Certora/uniswap-v4-periphery-cantina-fv",
]

ALLOWED_EXTS = {".spec", ".cvl", ".sol", ".yaml", ".yml", ".md", ".json", ".toml"}
# CVL rule/invariant declarations are genuine ONLY in these extensions.
CVL_DECL_EXTS = {".spec", ".cvl"}
# Bare assert/require lines are only scanned in code files (markdown prose uses
# the word "require" constantly and would otherwise create false positives).
CODE_EXTS = {".spec", ".cvl", ".sol"}
MAX_FILES = 3000
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_STATEMENT = 300

# Generic components of the governed repo names that are not protocol names.
GENERIC_TOKENS = {
    "certora", "competition", "periphery", "cantina", "formal", "verification",
    "audits", "audit", "repo", "recon", "fuzz", "spec", "specs", "rules",
    "test", "tests", "src", "main", "master",
}

RULE_RE = re.compile(r"^\s*rule\s+([A-Za-z0-9_]+)", re.M)
INVARIANT_RE = re.compile(r"^\s*invariant\s+([A-Za-z0-9_]+)", re.M)
PROPERTY_FN_RE = re.compile(
    r"\bfunction\s+((?:invariant|echidna|halmos|medusa)_[A-Za-z0-9_]*)\s*\(", re.M
)
GENERIC_FN_RE = re.compile(
    r"\bfunction\s+((?:test[A-Za-z0-9_]*|check_[A-Za-z0-9_]*|fuzz_[A-Za-z0-9_]*))\s*\(",
    re.M,
)
SETUP_FN_RE = re.compile(r"\bfunction\s+(setUp|constructor)\s*\(", re.M)
ASSERT_RE = re.compile(r"\b((?:assert|require)[A-Za-z0-9_]*)\b")
SHA40_RE = re.compile(r"\b[0-9a-fA-F]{40}\b")

# Exclusion decisions written into the candidate file.
EXCL_TEST_FN = "EXCLUDED_GENERIC_TEST_FUNCTION"
EXCL_SETUP_FN = "EXCLUDED_TEST_SETUP_HELPER"
EXCL_ASSERT = "EXCLUDED_BARE_ASSERTION"
EXCL_CONTEXT = "EXCLUDED_DECLARATION_CONTEXT"
ADMITTED_DECISION = "ADMITTED"

CONCRETE_VERDICTS = {"SUCCESS", "FAIL"}
LABEL_HELD = "property_held"
LABEL_VIOLATED = "property_violated"


# ---------------------------------------------------------------------------
# governance / provenance helpers
# ---------------------------------------------------------------------------
def load_formal_repos() -> list[str]:
    """Read the governed repo list from source_registry.jsonl."""
    repos: list[str] = []
    try:
        for row in read_jsonl(guard_scratch(SOURCE_REGISTRY)):
            if row.get("source_id") == SOURCE:
                repos = [str(r) for r in (row.get("repos") or []) if r]
                break
    except Exception as exc:  # pragma: no cover - defensive
        print(f"[formal] source_registry read failed: {exc}")
    return repos or list(FALLBACK_REPOS)


def git_head(dest: Path) -> str:
    """Return the clone's pinned HEAD sha (40 hex), or '' if unavailable."""
    try:
        proc = subprocess.run(
            ["git", "-C", str(dest), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        sha = (proc.stdout or "").strip()
        if SHA40_RE.fullmatch(sha):
            return sha.lower()
    except Exception:  # pragma: no cover - git absent / timeout
        pass
    return ""


def iter_files(dest: Path) -> Iterable[Path]:
    """Walk a clone, skipping .git, capped by count and per-file size."""
    scanned = 0
    for root, dirs, files in os.walk(dest):
        dirs[:] = sorted(d for d in dirs if d != ".git")
        for name in sorted(files):
            path = Path(root) / name
            if path.suffix.lower() not in ALLOWED_EXTS:
                continue
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            scanned += 1
            if scanned > MAX_FILES:
                return
            yield path


# ---------------------------------------------------------------------------
# extraction
# ---------------------------------------------------------------------------
def _candidate_decision(kind: str, ext: str) -> str:
    """Decide admission at extraction time; reasons are recorded verbatim."""
    if kind in ("rule", "invariant"):
        return ADMITTED_DECISION if ext.lower() in CVL_DECL_EXTS else EXCL_CONTEXT
    if kind == "property_function":
        return ADMITTED_DECISION
    if kind == "function":
        return EXCL_TEST_FN
    if kind == "setup_helper":
        return EXCL_SETUP_FN
    return EXCL_ASSERT


def extract_matches(text: str, ext: str) -> list[dict[str, Any]]:
    """One best match per line: rule > invariant > property fn > test > setup > assert.

    Every match is returned, including the excluded ones, so the candidate file
    is a complete, auditable record of what was seen and why it was dropped.
    """
    lines = text.splitlines()
    allow_assertions = ext.lower() in CODE_EXTS
    out: list[dict[str, Any]] = []
    for idx, line in enumerate(lines):
        kind = ""
        name = ""
        match = RULE_RE.match(line)
        if match:
            kind, name = "rule", match.group(1)
        else:
            match = INVARIANT_RE.match(line)
            if match:
                kind, name = "invariant", match.group(1)
            else:
                match = PROPERTY_FN_RE.search(line)
                if match:
                    kind, name = "property_function", match.group(1)
                else:
                    match = GENERIC_FN_RE.search(line)
                    if match:
                        kind, name = "function", match.group(1)
                    else:
                        match = SETUP_FN_RE.search(line)
                        if match:
                            kind, name = "setup_helper", match.group(1)
                        elif allow_assertions:
                            match = ASSERT_RE.search(line)
                            if match:
                                kind, name = "assertion", match.group(1)
        if not kind:
            continue
        context = " ".join(lines[max(0, idx - 5): idx + 6])
        out.append(
            {
                "line_no": idx + 1,
                "name": name,
                "kind": kind,
                "context": context,
                "decision": _candidate_decision(kind, ext),
            }
        )
    return out


def property_statement(lines: list[str], idx: int) -> str:
    """Declaration line plus up to 2 following non-empty lines, <=300 chars."""
    parts = [lines[idx].strip()]
    taken = 0
    cursor = idx + 1
    while cursor < len(lines) and taken < 2:
        nxt = lines[cursor].strip()
        if nxt:
            parts.append(nxt)
            taken += 1
        cursor += 1
    stmt = re.sub(r"\s+", " ", " ".join(p for p in parts if p)).strip()
    return stmt[:MAX_STATEMENT]


def infer_tool(ext: str, name: str, kind: str, context: str) -> str:
    """Infer cvl / echidna / halmos / medusa / foundry from observed syntax."""
    low = context.lower()
    if name.startswith("echidna_"):
        return "echidna"
    if name.startswith("medusa_"):
        return "medusa"
    if name.startswith("halmos_") or "halmos" in low:
        return "halmos"
    if name.startswith("invariant_"):
        return "foundry_invariant"
    if ext.lower() in CVL_DECL_EXTS or kind in ("rule", "invariant"):
        return "cvl"
    if "certora" in low:
        return "cvl"
    if "medusa" in low:
        return "medusa"
    if "echidna" in low:
        return "echidna"
    return "foundry"


def protocol_tokens(slug: str) -> list[str]:
    name = slug.split("/")[-1].lower()
    return [
        tok
        for tok in re.findall(r"[a-z0-9]+", name)
        if len(tok) >= 3 and tok not in GENERIC_TOKENS
    ]


def certora_pointers(registry: dict[str, dict]) -> list[tuple[str, str, str]]:
    """The 200 report-level keys already resident in jsonl_v3/findings.jsonl."""
    ptrs: list[tuple[str, str, str]] = []
    for key, row in registry.items():
        if key.startswith("certora_rule:certora-reports:"):
            value = str(row.get("value") or key)
            normalized = re.sub(r"[^a-z0-9]+", " ", value.lower()).strip()
            ptrs.append((key, value, normalized))
    return ptrs


def certora_cover(rule_id: str, tokens: list[str],
                  ptrs: list[tuple[str, str, str]]) -> tuple[str, str] | None:
    """Return the covering certora pointer (key, value), or None.

    A rule from a NEW governed repo (gho-competition / uniswap-v4-cantina-fv /
    Recon-Fuzz) is only a cross-layer duplicate of a V3 report pointer when the
    FULL report identity matches — not when a single generic protocol token
    like "gho" or "uniswap" appears in an unrelated SecurityReports pointer.
    Matching one token would incorrectly drop every rule of the two new Certora
    suites, so require a specific (>=8 char) normalized substring overlap.
    """
    rule_norm = re.sub(r"[^a-z0-9]+", "", rule_id.lower())
    for key, value, _normalized in ptrs:
        ptr_norm = re.sub(r"[^a-z0-9]+", "", value.lower())
        if len(ptr_norm) < 8 or len(rule_norm) < 8:
            continue
        if ptr_norm in rule_norm or rule_norm in ptr_norm:
            return key, value
    return None


# ---------------------------------------------------------------------------
# observed verdict matrices (pair evidence)
# ---------------------------------------------------------------------------
def _matrix_variants(status_row: list[str], header: list[str]) -> list[tuple[str, str]]:
    """Turn one CSV result row into [(variant_id, observed_status), ...]."""
    variants: list[tuple[str, str]] = []
    for idx, raw in enumerate(status_row[1:], start=1):
        col = header[idx] if idx < len(header) else f"col{idx}"
        vid = col.split("_", 1)[0] or col
        variants.append((vid, str(raw or "").strip()))
    return variants


def _build_evidence(name: str, path: Path, rel: str, priority: int,
                    variants: list[tuple[str, str]], dir_hint: str) -> dict[str, Any]:
    """Summarize one committed result matrix for a named rule."""
    clean = ""
    failing: list[str] = []
    passing: list[str] = []
    for vid, status in variants:
        if vid.lower() == "original":
            clean = status
            continue
        if status in CONCRETE_VERDICTS:
            (failing if status == "FAIL" else passing).append(vid)
    concrete = [s for _v, s in variants if s in CONCRETE_VERDICTS]
    return {
        "name": name,
        "evidence_file": rel,
        "priority": priority,
        "dir_hint": dir_hint,
        "variants": variants,
        "clean_status": clean,
        "failing_mutants": sorted(set(failing)),
        "passing_mutants": sorted(set(passing)),
        "has_success": "SUCCESS" in concrete,
        "has_fail": "FAIL" in concrete,
    }


def load_pair_evidence(dest: Path, slug_norm: str) -> dict[str, dict[str, Any]]:
    """Read committed Certora result matrices in a clone (clean + mutants).

    Sources: repo-root results.json (canonical) and all
    ``*/mutations/coverage/*.csv`` matrices.  Statuses other than SUCCESS/FAIL
    (e.g. TIMEOUT/UNKNOWN/SANITY_FAIL) are recorded but never treated as a
    verdict.  One deterministic matrix per rule name is kept (root results.json
    wins over per-contestant CSVs, then lexicographic path).
    """
    found: dict[str, list[dict[str, Any]]] = defaultdict(list)

    root_json = dest / "results.json"
    if root_json.exists() and root_json.stat().st_size <= MAX_FILE_BYTES:
        try:
            data = json.loads(guard_scratch(root_json).read_text(encoding="utf-8"))
            by_name: dict[str, list[tuple[str, str]]] = defaultdict(list)
            order: list[str] = []
            for version in data if isinstance(data, list) else []:
                vid = str(version.get("id") or "Original")
                for rule in version.get("rules") or []:
                    name = str(rule.get("name") or "")
                    if not name:
                        continue
                    if name not in by_name:
                        order.append(name)
                    by_name[name].append((vid, str(rule.get("status") or "")))
            for name in order:
                found[name].append(
                    _build_evidence(name, root_json, "results.json", 0,
                                    by_name[name], "")
                )
        except Exception as exc:  # pragma: no cover - defensive
            print(f"[formal] results.json read failed for {slug_norm}: {exc}")

    for path in sorted(dest.rglob("mutations/coverage/*.csv")):
        if ".git" in path.parts:
            continue
        try:
            guard_scratch(path)
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            with open(path, encoding="utf-8", newline="") as fh:
                reader = csv.reader(fh)
                header = next(reader, [])
                for row in reader:
                    if not row or not row[0].strip():
                        continue
                    name = row[0].strip()
                    rel = path.relative_to(dest).as_posix()
                    dir_hint = rel.split("/", 1)[0] if "/" in rel else ""
                    found[name].append(
                        _build_evidence(name, path, rel, 2,
                                        _matrix_variants(row, header), dir_hint)
                    )
        except Exception as exc:  # pragma: no cover - defensive
            print(f"[formal] coverage matrix read failed for {slug_norm}: {exc}")

    chosen: dict[str, dict[str, Any]] = {}
    for name, records in found.items():
        records.sort(key=lambda r: (r["priority"], r["evidence_file"]))
        chosen[name] = records[0]
    return chosen


def pair_evidence_text(ev: dict[str, Any]) -> str:
    """Short, factual description of the observed clean-vs-mutant pair."""
    clean = ev["clean_status"] or "not-observed"
    fail = ", ".join(ev["failing_mutants"][:5]) or "none"
    passed = ", ".join(ev["passing_mutants"][:5]) or "none"
    return (
        f"Committed Certora Prover result matrix {ev['evidence_file']}: "
        f"Original(clean)={clean}; mutants FAIL=[{fail}]; "
        f"mutants SUCCESS=[{passed}]; verdicts observed in source, not inferred"
    )


# ---------------------------------------------------------------------------
# append-only helper (the overlap manifest is shared)
# ---------------------------------------------------------------------------
def existing_manifest_keys() -> set[tuple[Any, ...]]:
    seen: set[tuple[Any, ...]] = set()
    if OVERLAP.exists():
        try:
            for row in read_jsonl(OVERLAP):
                seen.add((row.get("source"), row.get("candidate_id"), row.get("key")))
        except Exception:  # pragma: no cover - defensive
            pass
    return seen


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main() -> None:
    notes: list[str] = []
    repos = load_formal_repos()
    notes.append(f"governed repos={len(repos)}; metadata_only=true")
    registry = load_registry()
    pointers = certora_pointers(registry)
    notes.append(f"canonical registry keys={len(registry)}; certora report pointers={len(pointers)}")

    heads: dict[str, str] = {}
    evidence_by_repo: dict[str, dict[str, dict[str, Any]]] = {}
    candidates: list[dict[str, Any]] = []
    files_scanned = 0
    skipped_by_cap = 0

    for slug in repos:
        slug_norm = norm_repo_slug(slug)
        clone_name = slug.replace("/", "__")
        try:
            dest = git_clone("https://github.com/" + slug, clone_name)
        except Exception as exc:  # pragma: no cover - defensive
            dest = None
            notes.append(f"clone error {slug}: {exc}")
        if dest is None or not (dest / ".git").exists():
            notes.append(f"clone unavailable; skipped {slug}")
            continue
        try:
            guard_scratch(dest)
        except PermissionError as exc:
            notes.append(f"clone outside scratch; skipped {slug}: {exc}")
            continue
        head = git_head(dest)
        heads[slug] = head
        if not head:
            notes.append(f"HEAD unavailable for {slug}; pinned_commit may come from in-file sha40")

        evidence_by_repo[slug_norm] = load_pair_evidence(dest, slug_norm)
        notes.append(
            f"{slug_norm}: observed verdict matrices={len(evidence_by_repo[slug_norm])} "
            f"({sum(1 for e in evidence_by_repo[slug_norm].values() if e['has_fail'])} "
            "with a concrete FAIL)"
        )

        repo_files = 0
        for path in iter_files(dest):
            repo_files += 1
            try:
                rel = path.relative_to(dest).as_posix()
                text = path.read_text(encoding="utf-8", errors="replace")
            except Exception as exc:
                notes.append(f"read failed {slug}: {exc}")
                continue
            files_scanned += 1
            nearby = ids_from_text(text)["sha40"]
            pinned = head or (nearby[0] if nearby else "")
            lines = text.splitlines()
            ext = path.suffix.lower()
            for match in extract_matches(text, ext):
                line_no = int(match["line_no"])
                name = str(match["name"])
                kind = str(match["kind"])
                rule_id = f"{rel}:{name}:{line_no}"
                statement = property_statement(lines, line_no - 1)
                if not statement:
                    continue
                tool = infer_tool(ext, name, kind, str(match["context"]))
                candidate_id = f"{slug_norm}:{rule_id}"
                candidates.append(
                    {
                        "source": SOURCE,
                        "candidate_id": candidate_id,
                        "repo_slug": slug_norm,
                        "rule_id": rule_id,
                        "file_path": rel,
                        "line_no": line_no,
                        "property_statement": statement,
                        "pinned_commit": pinned,
                        "tool": tool,
                        "decl_kind": kind,
                        "rule_name": name,
                        "protocol_tokens": protocol_tokens(slug),
                        # METADATA_ONLY: a verdict flag is only set when a
                        # concrete Original verdict was observed in source.
                        "verdict_flag": "",
                        "evidence_type": "observed_fact",
                        "dedup_keys": [
                            f"formal_rule:{slug_norm}:{rule_id}",
                            f"formal_repo:{slug_norm}",
                        ],
                        "retrieved_at": utc_now(),
                        "decision": str(match["decision"]),
                    }
                )
        if repo_files >= MAX_FILES:
            skipped_by_cap += 1
            notes.append(f"file cap {MAX_FILES} reached for {slug}")
        print(f"[formal] {slug}: scanned {repo_files} files, {len(candidates)} cumulative matches")

    # ------------------------------------------------------------------
    # dedup / admission
    # ------------------------------------------------------------------
    admitted: list[dict[str, Any]] = []
    overlap_new: list[dict[str, Any]] = []
    seen_rules: set[str] = set()
    seen_manifest = existing_manifest_keys()
    counts: Counter[str] = Counter()

    def add_overlap(candidate: dict[str, Any], key: str, layer: Any,
                    value: Any, decision: str) -> None:
        signature = (SOURCE, candidate["candidate_id"], key)
        if signature in seen_manifest:
            return
        seen_manifest.add(signature)
        overlap_new.append(
            {
                "source": SOURCE,
                "candidate_id": candidate["candidate_id"],
                "key": key,
                "duplicate_of_layer": layer,
                "duplicate_of_value": value,
                "decision": decision,
            }
        )

    for cand in candidates:
        cid = cand["candidate_id"]
        # Non-property matches are recorded but never admitted.
        if cand["decision"] != ADMITTED_DECISION:
            counts[cand["decision"]] += 1
            continue
        # A rule_id is unique within a repo; collapse repeats from the scan.
        if cand["rule_id"] in seen_rules:
            cand["decision"] = "DROPPED_IN_RUN_DUPLICATE"
            counts["other_collisions"] += 1
            add_overlap(cand, f"formal_rule:{cand['repo_slug']}:{cand['rule_id']}",
                        SOURCE, cid, "DROPPED_IN_RUN_DUPLICATE")
            continue
        seen_rules.add(cand["rule_id"])

        # check_keys is applied per dedup key; ANY hit drops the row.  The
        # shared formal_repo:<slug> key does the right thing if it collides.
        hits = check_keys(cand["dedup_keys"], registry)
        if hits:
            cand["decision"] = "DROPPED_DEDUP_KEY"
            counts["other_collisions"] += 1
            for hit in hits:
                if hit.get("key"):
                    add_overlap(cand, hit["key"], hit.get("layer"),
                                hit.get("value"), "DROPPED_CROSS_LAYER_DUPLICATE")
            continue

        # Cross-layer guard: an existing certora-reports pointer for this
        # protocol already carries this finding in jsonl_v3.  Requires a FULL
        # report-identity match, never a single protocol token.
        cover = certora_cover(cand["rule_id"], cand["protocol_tokens"], pointers)
        if cover:
            key, value = cover
            cand["decision"] = "DROPPED_CERTORA_POINTER"
            counts["certora_pointer_collisions"] += 1
            add_overlap(cand, key, "V3", value, "DROPPED_CERTORA_REPORT_POINTER")
            continue

        cand["decision"] = ADMITTED_DECISION
        admitted.append(cand)

    # ------------------------------------------------------------------
    # attach honest pair evidence (one audited matrix per named rule)
    # ------------------------------------------------------------------
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in admitted:
        groups[(row["repo_slug"], row["rule_name"])].append(row)

    paired: dict[str, dict[str, Any]] = {}
    for (slug, name), rows in sorted(groups.items()):
        ev = (evidence_by_repo.get(slug) or {}).get(name)
        if ev is None or not (ev["has_success"] or ev["has_fail"]):
            continue
        rows.sort(key=lambda r: r["candidate_id"])
        hint = ev["dir_hint"]
        preferred = [r for r in rows if hint and r["file_path"].startswith(hint + "/")]
        chosen = (preferred or rows)[0]
        paired[chosen["candidate_id"]] = ev

    for row in admitted:
        ev = paired.get(row["candidate_id"])
        if ev is not None:
            row["quality"] = {"invariants": "high"}
            row["verification_status"] = "observed_prover_verdict_in_source"
            row["pair_evidence"] = pair_evidence_text(ev)
            # Only the concrete Original verdict is used as a flag; mutant
            # outcomes stay in pair_evidence so no verdict is over-claimed.
            row["verdict_flag"] = ev["clean_status"] if ev["clean_status"] in CONCRETE_VERDICTS else ""
        else:
            row["quality"] = {"invariants": "unverified"}
            row["verification_status"] = "observed_declaration_unverified"
            row["pair_evidence"] = ""
            row["verdict_flag"] = ""

    admitted_out: list[dict[str, Any]] = []
    for cand in admitted:
        admitted_out.append(
            {
                "source": SOURCE,
                "candidate_id": cand["candidate_id"],
                "repo_slug": cand["repo_slug"],
                "rule_id": cand["rule_id"],
                "file_path": cand["file_path"],
                "line_no": cand["line_no"],
                "property_statement": cand["property_statement"],
                "pinned_commit": cand["pinned_commit"],
                "tool": cand["tool"],
                "quality": cand["quality"],
                "verification_status": cand["verification_status"],
                "verdict_flag": cand["verdict_flag"],
                "pair_evidence": cand["pair_evidence"],
                "decl_kind": cand["decl_kind"],
                "rule_name": cand["rule_name"],
                "evidence_type": cand["evidence_type"],
                "dedup_keys": cand["dedup_keys"],
                "retrieved_at": cand["retrieved_at"],
                "decision": ADMITTED_DECISION,
            }
        )

    # ------------------------------------------------------------------
    # benchmark: rewrite from scratch, paired rows only, honest labels
    # ------------------------------------------------------------------
    inv_rows: list[dict[str, Any]] = []
    for row in sorted(admitted_out, key=lambda r: r["candidate_id"]):
        cid = row["candidate_id"]
        ev = paired.get(cid)
        if ev is None:
            continue  # declaration-only: no truthful label, no benchmark row
        success_variant = ""
        fail_variant = ""
        if ev["clean_status"] == "SUCCESS":
            success_variant = "Original"
        if ev["clean_status"] == "FAIL":
            fail_variant = "Original"
        if not success_variant:
            success_variant = next((v for v in ev["passing_mutants"]), "")
        if not fail_variant:
            fail_variant = next((v for v in ev["failing_mutants"]), "")
        emitted: list[tuple[str, str, str]] = []
        if success_variant:
            emitted.append((LABEL_HELD, "SUCCESS", success_variant))
        if fail_variant:
            emitted.append((LABEL_VIOLATED, "FAIL", fail_variant))
        for label, answer, variant in emitted:
            task_id = "formal:" + sha256_text(f"{cid}|{label}|{variant}")[:12]
            # Deterministic 70/15/15 split keyed by repo slug + task id so a
            # rule name cannot leak across splits from the same repo.
            bucket = int(sha256_text(f"{row['repo_slug']}|{task_id}|split"), 16) % 100
            split = "train" if bucket < 70 else ("val" if bucket < 85 else "test")
            inv_rows.append(
                {
                    "task_id": task_id,
                    "candidate_id": cid,
                    "label": label,
                    "answer": answer,
                    "split": split,
                    "repo_slug": row["repo_slug"],
                    "property_statement": row["property_statement"],
                    "pair_evidence": row["pair_evidence"],
                    "verdict_variant": variant,
                    "evidence_source": ev["evidence_file"],
                }
            )

    # ------------------------------------------------------------------
    # write outputs
    # ------------------------------------------------------------------
    write_jsonl(guard_wave1(CANDIDATES), candidates)
    write_jsonl(guard_wave1(ADMITTED), admitted_out)
    appended_overlap = append_jsonl(guard_wave1(OVERLAP), overlap_new)
    # REWRITE (not append) so reruns are idempotent and never duplicate rows.
    written_invariants = write_jsonl(guard_wave1(INVARIANTS), inv_rows)

    by_tool = Counter(r["tool"] for r in admitted_out)
    cvl_rules = sum(1 for r in admitted_out if r["decl_kind"] == "rule")
    cvl_invariants = sum(1 for r in admitted_out if r["decl_kind"] == "invariant")
    property_functions = sum(1 for r in admitted_out if r["decl_kind"] == "property_function")
    high_quality = sum(1 for r in admitted_out if r["quality"]["invariants"] == "high")
    declaration_only = len(admitted_out) - high_quality
    benchmark_labels = dict(sorted(Counter(r["label"] for r in inv_rows).items()))
    split_distribution = dict(sorted(Counter(r["split"] for r in inv_rows).items()))

    per_repo: dict[str, dict[str, int]] = {}
    for cand in candidates:
        bucket = per_repo.setdefault(cand["repo_slug"], Counter())
        bucket["found"] += 1
        bucket[cand["decision"]] += 1
    repo_notes = [
        f"{slug}: found={d['found']} admitted={d[ADMITTED_DECISION]} "
        f"test_fns={d[EXCL_TEST_FN]} setup={d[EXCL_SETUP_FN]} "
        f"assertions={d[EXCL_ASSERT]} prose_decls={d[EXCL_CONTEXT]}"
        for slug, d in sorted(per_repo.items())
    ]

    report = {
        "generated_at": utc_now(),
        "source": SOURCE,
        "repos_attempted": len(repos),
        "repos_cloned": len(heads),
        "files_scanned": files_scanned,
        "rules_found": len(candidates),
        "excluded_test_functions": counts[EXCL_TEST_FN],
        "excluded_setup_helpers": counts[EXCL_SETUP_FN],
        "excluded_bare_assertions": counts[EXCL_ASSERT],
        "excluded_declaration_context": counts[EXCL_CONTEXT],
        "excluded_certora_pointer": counts["certora_pointer_collisions"],
        "excluded_duplicate": counts["other_collisions"],
        "admitted": len(admitted_out),
        "admitted_by_tool": dict(sorted(by_tool.items())),
        "high_quality_admitted": high_quality,
        "declaration_only": declaration_only,
        "benchmark_rows_emitted": written_invariants,
        "benchmark_labels": benchmark_labels,
        "split_distribution": split_distribution,
        "certora_pointer_collisions": counts["certora_pointer_collisions"],
        "other_collisions": counts["other_collisions"],
        "overlap_rows_appended": appended_overlap,
        "pinned_heads": heads,
        "per_repo": {slug: dict(sorted(d.items())) for slug, d in sorted(per_repo.items())},
        "notes": notes
        + repo_notes
        + [
            "STRICT ADMISSION: only CVL rule/invariant declarations in .spec/.cvl "
            "and named invariant_*/echidna_*/halmos_*/medusa_* property functions "
            "are admitted; rule/invariant tokens in prose (.md) are excluded",
            f"exact admitted CVL declarations={cvl_rules + cvl_invariants} "
            f"({cvl_rules} rule + {cvl_invariants} invariant); named "
            f"invariant_*/echidna_*/halmos_*/medusa_* property functions observed="
            f"{property_functions}; the prior 'cvl=3180' tool tally was inflated by "
            "~2175 bare assert/require lines inside .spec files, which are now "
            "correctly excluded as non-properties",
            f"excluded_test_functions={counts[EXCL_TEST_FN]}: generic Foundry "
            "test*/check_*/fuzz_* functions are not formal properties",
            f"excluded_setup_helpers={counts[EXCL_SETUP_FN]}: setUp/constructor "
            "are test harness setup, not properties",
            f"excluded_bare_assertions={counts[EXCL_ASSERT]}: assert/require lines "
            "carry no named property and no observed verdict; scan limited to "
            f"code extensions {sorted(CODE_EXTS)} to avoid markdown-prose false positives",
            "quality=high and pair_evidence are set ONLY from a committed Certora "
            "Prover result matrix (Original vs mutants); all other admissions are "
            "unverified/observed_declaration_unverified",
            "invariants.jsonl is rewritten from scratch each run (no appends); "
            "labels are strictly property_violated/property_held and answer is the "
            "observed verdict string SUCCESS/FAIL",
            "verdict_flag is set only to a concrete observed Original verdict; "
            "mutant outcomes stay in pair_evidence so no verdict is over-claimed",
            "certora pointer match requires a FULL report-identity substring (>=8 "
            "chars) against the 200 certora-reports:* keys; a single protocol token "
            "(gho/uniswap) is NOT a collision because the new repos are distinct",
        ]
        + ([f"file cap {MAX_FILES} reached in {skipped_by_cap} repo(s)"] if skipped_by_cap else []),
    }
    write_json(guard_wave1(REPORT), report)

    print(
        f"[formal] repos={len(heads)}/{len(repos)} files={files_scanned} "
        f"rules_found={len(candidates)} admitted={len(admitted_out)} "
        f"high={high_quality} declaration_only={declaration_only} "
        f"benchmark_rows={written_invariants} labels={benchmark_labels} "
        f"splits={split_distribution} overlap_appended={appended_overlap}"
    )
    print(
        f"[formal] excluded: test_functions={counts[EXCL_TEST_FN]} "
        f"setup_helpers={counts[EXCL_SETUP_FN]} bare_assertions={counts[EXCL_ASSERT]} "
        f"prose_declarations={counts[EXCL_CONTEXT]}"
    )
    print(f"[formal] admitted_by_tool={report['admitted_by_tool']}")
    print(f"[formal] report -> {REPORT}")


if __name__ == "__main__":
    main()
