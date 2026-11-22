"""hydrate_wave1.py -- verbatim hydration of all Wave-1 candidate families.

Stdlib only. Writes ONLY inside wave1/ (plus the authorised log at
reports/_wave1_hydration_log.md and the git-ignored work/hydration_cache/).

For every stub/partial row in wave1/03_candidates/** this script tries a set of
CONFIRMED extraction recipes (see reports/_recon_sample_hydration_probes.md).
A row is admitted to the hydrated candidate layer only when a real source yields
  * >=50 chars of inline code, and
  * >=100 chars of prose,
both copied verbatim.  Every other row is moved, with its full original body,
into wave1/01_dedup/hydration_quarantine.jsonl with an UNHYDRATABLE_DEAD_POINTER
marker.  No field is invented, paraphrased or inferred from a title.

Usage:
    python scripts/hydrate_wave1.py            # full run
    python scripts/hydrate_wave1.py --family judge
    python scripts/hydrate_wave1.py --dry-run  # report counts, write nothing
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "wave1" / "scripts"))

from _common import (  # noqa: E402
    WAVE1, guard_wave1, read_jsonl, utc_now, write_json, write_jsonl,
)
from hydration_lib import (  # noqa: E402
    CODE_MIN, PROSE_MIN, FORMAL_LOCAL, MD_LOCAL, OZ_LOCAL, REVM_LOCAL,
    add_inline, fenced_code, judge_quote_for, load_api_index, prose_from_body, quarantine, raw_fetch, raw_from_blob, fully_trainable,
)

CAND = WAVE1 / "03_candidates"
QUARANTINE = WAVE1 / "01_dedup" / "hydration_quarantine.jsonl"
LOG = ROOT / "reports" / "_wave1_hydration_log.md"

FAMILIES = {
    "c4_mitigation": CAND / "c4_mitigation" / "issues.jsonl",
    "reevmbench": CAND / "reevmbench" / "harnesses.jsonl",
    "formal_specs": CAND / "formal_specs" / "rules.jsonl",
    "judge": CAND / "judge" / "issues.jsonl",
    "markdown_two_revision": CAND / "markdown_two_revision" / "candidates.jsonl",
    "ghsa_web3_netnew": CAND / "ghsa_web3_netnew" / "candidates.jsonl",
}


# ---------------------------------------------------------------------------
# per-family verbatim hydrators -> (row_or_None, reason_if_None)
# ---------------------------------------------------------------------------
def hydrate_c4(row: dict, issues: dict, comments: dict):
    issue = issues.get(str(row.get("permalink") or "")) or issues.get(str(row.get("issue_url") or ""))
    if not issue:
        return None, "no cached issue object for permalink/issue_url"
    body = str(issue.get("body") or "")
    code, prose = code_from_body_safe(body), prose_from_body(body)
    if len(code) < CODE_MIN or len(prose) < PROSE_MIN:
        return None, f"body code={len(code)} prose={len(prose)} below thresholds"
    out = add_inline(row, code_blocks=[code], prose=prose,
                     code_file=str(row.get("repo_slug") or ""),
                     source=f"_api_cache issue {row.get('permalink')}")
    # A real sponsor fix commit may carry a verbatim unified diff (optional).
    fix = str(row.get("fixed_commit") or "")
    if len(fix) == 40:
        repo = str(row.get("repo_slug") or "")
        diff = raw_fetch(f"https://github.com/{repo}/commit/{fix}.diff")
        if diff and "diff --git" in diff:
            out = add_inline(out, diff=diff, source=out.get("hydration_source", ""))
    return out, ""


def hydrate_judge(row: dict, issues: dict, comments: dict):
    issue = issues.get(str(row.get("permalink") or ""))
    if not issue:
        return None, "no cached issue object for permalink"
    body = str(issue.get("body") or "")
    code, prose = code_from_body_safe(body), prose_from_body(body)
    if len(code) < CODE_MIN or len(prose) < PROSE_MIN:
        return None, f"bare-label row: code={len(code)} prose={len(prose)}"
    quote = judge_quote_for(issue, comments)
    out = add_inline(row, code_blocks=[code], prose=prose, judge_quote=quote,
                     code_file=str(row.get("repo_slug") or ""),
                     source=f"_api_cache issue {row.get('permalink')}")
    return out, ""


def hydrate_formal(row: dict, issues: dict, comments: dict):
    root = FORMAL_LOCAL.get(str(row.get("repo_slug") or ""))
    fpath, line = str(row.get("file_path") or ""), int(row.get("line_no") or 0)
    text, local = "", False
    if root is not None:
        p = root / fpath
        if p.exists():
            text = p.read_text(encoding="utf-8", errors="replace")
            local = True
    if not text:
        raw = f"https://raw.githubusercontent.com/{row.get('repo_slug')}/{row.get('pinned_commit')}/{fpath}"
        text = raw_fetch(raw) or ""
    if not text:
        return None, "formal source file not resolvable locally or via raw GitHub"
    window = "\n".join(text.splitlines()[max(0, line - 1 - 6):line + 14]).strip()
    if len(window) < CODE_MIN:
        return None, f"rule window code={len(window)} below threshold"
    prose = comment_prose_from_text(text) if fpath.lower().endswith((".spec", ".sol")) else prose_from_body(text)
    if len(prose) < PROSE_MIN:
        return None, f"rule source prose={len(prose)} below threshold"
    out = add_inline(row, code_blocks=[window], prose=prose, rule_body=window,
                     target_code=window, code_file=fpath,
                     code_function=str(row.get("rule_name") or ""),
                     source=("local:" if local else "raw:") + f"{row.get('repo_slug')}/{fpath}")
    return out, ""


def hydrate_markdown(row: dict, issues: dict, comments: dict):
    text = ""
    p = MD_LOCAL / str(row.get("file_path") or "")
    if p.exists():
        text = p.read_text(encoding="utf-8", errors="replace")
        src = "local:" + str(row.get("file_path"))
    else:
        # mixbytes/audits_public: deterministic raw fetch of the pinned permalink
        ref, path, _rng, fetched = raw_from_blob(str(row.get("permalink") or ""))
        if fetched:
            text, src = fetched, "raw:" + str(row.get("permalink"))
        else:
            return None, "advisory Markdown not resolvable locally or via raw GitHub"
    code, prose = fenced_code(text), prose_from_body(text)
    if len(code) < CODE_MIN or len(prose) < PROSE_MIN:
        return None, f"advisory code={len(code)} prose={len(prose)} below thresholds"
    out = add_inline(row, code_blocks=[code], prose=prose,
                     code_file=str(row.get("file_path") or ""), source=src)
    fix, repo = str(row.get("fix_commit") or ""), str(row.get("repo_slug") or "")
    if len(fix) == 40 and "mixbytes" in repo:
        diff = raw_fetch(f"https://github.com/{repo}/commit/{fix}.diff")
        if diff and "diff --git" in diff:
            out = add_inline(out, diff=diff, source=src)
    return out, ""


def hydrate_reevmbench(row: dict, issues: dict, comments: dict):
    d = REVM_LOCAL / str(row.get("harness_path") or "")
    if not d.exists():
        return None, "harness directory not present in local ReEVMBench clone"
    mds = sorted(d.rglob("*.md"))
    if not mds:
        return None, "harness has no Markdown audit/hint file"
    text = ""
    for md in mds:
        t = md.read_text(encoding="utf-8", errors="replace")
        if len(t) > len(text):
            text = t
    code, prose = fenced_code(text), prose_from_body(text)
    if len(code) < CODE_MIN or len(prose) < PROSE_MIN:
        return None, f"harness code={len(code)} prose={len(prose)} below thresholds"
    poc = ""
    for sol in d.rglob("*.sol"):
        t = sol.read_text(encoding="utf-8", errors="replace")
        if len(t) > len(poc):
            poc = t
    if not poc:
        for md in mds:
            fc = fenced_code(md.read_text(encoding="utf-8", errors="replace"))
            if len(fc) > len(poc):
                poc = fc
    out = add_inline(row, code_blocks=[code], prose=prose, poc=poc,
                     code_file=str(row.get("harness_path") or ""),
                     source="local:" + str(row.get("harness_path")))
    return out, ""


def hydrate_ghsa(row: dict, issues: dict, comments: dict):
    fix = str(row.get("fix_commit") or "")
    sol = ""
    if OZ_LOCAL.exists():
        for p in OZ_LOCAL.rglob("*.sol"):
            if fix and fix[:12] == p.parent.name[:12]:
                sol = p.read_text(encoding="utf-8", errors="replace")
                break
        if not sol:
            cands = [p for p in OZ_LOCAL.rglob("*.sol")]
            if cands:
                sol = sorted(cands)[0].read_text(encoding="utf-8", errors="replace")
    code = fenced_code(sol) or sol[:800]
    # The GHSA advisory prose is NOT in the local _api_cache (2,035 objects
    # cover C4 issues only) and the advisory-database raw path is not pinned on
    # this row.  Without a verbatim prose source the row is unhydratable.
    prose = ""
    if len(code) < CODE_MIN or len(prose) < PROSE_MIN:
        return None, "GHSA advisory prose not resolvable from local cache without fabrication"
    return add_inline(row, code_blocks=[code], prose=prose, source="local:OpenZeppelin"), ""


# helpers that avoid importing private regexes from hydration_lib
def code_from_body_safe(body: str) -> str:
    from hydration_lib import code_from_body
    return code_from_body(body)


def comment_prose_from_text(text: str) -> str:
    lines = []
    for raw in text.splitlines():
        s = raw.strip()
        if s.startswith(("//", "#", "/*", "*", "///", "//!")):
            cleaned = s.lstrip("/#*! ").strip("*/ \t")
            if len(cleaned) >= 4:
                lines.append(cleaned)
    return "\n".join(lines)


HYDRATORS = {
    "c4_mitigation": hydrate_c4,
    "judge": hydrate_judge,
    "formal_specs": hydrate_formal,
    "markdown_two_revision": hydrate_markdown,
    "reevmbench": hydrate_reevmbench,
    "ghsa_web3_netnew": hydrate_ghsa,
}


# ---------------------------------------------------------------------------
# driver
# ---------------------------------------------------------------------------
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--family", choices=sorted(FAMILIES))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    issues, comments = load_api_index()
    families = {args.family: FAMILIES[args.family]} if args.family else FAMILIES
    # Quarantine is a cumulative ledger: rebuilding the candidate layer must
    # never erase rows purged in an earlier pass.
    ledger: dict[str, dict] = {}
    if QUARANTINE.exists():
        for old in read_jsonl(guard_wave1(QUARANTINE)):
            key = str(old.get("candidate_id") or json.dumps(old, sort_keys=True))
            ledger[key] = old
    summary: dict[str, dict] = {}
    started = time.time()

    for fam, path in families.items():
        rows = list(read_jsonl(guard_wave1(path)))
        kept, dead = [], []
        for row in rows:
            # already-hydrated rows pass through untouched
            if fully_trainable(row):
                kept.append(row)
                continue
            out, reason = HYDRATORS[fam](row, issues, comments)
            if out is not None and fully_trainable(out):
                kept.append(out)
            else:
                dead.append(quarantine(row, reason or "no verbatim source met thresholds"))
        summary[fam] = {
            "before": len(rows),
            "hydrated": len(kept),
            "quarantined": len(dead),
            "already_hydrated": sum(1 for r in rows if fully_trainable(r)),
        }
        if not args.dry_run:
            write_jsonl(guard_wave1(path), kept)
            for q in dead:
                key = str(q.get("candidate_id") or json.dumps(q, sort_keys=True))
                ledger[key] = q
        print(f"[hydrate:{fam}] before={len(rows)} hydrated={len(kept)} quarantined={len(dead)}")

    if not args.dry_run:
        write_jsonl(guard_wave1(QUARANTINE), ledger.values())
        payload = {
            "generated_at": utc_now(),
            "seconds": round(time.time() - started, 2),
            "thresholds": {"code_chars_min": CODE_MIN, "prose_chars_min": PROSE_MIN},
            "families": summary,
            "totals": {
                "before": sum(s["before"] for s in summary.values()),
                "hydrated": sum(s["hydrated"] for s in summary.values()),
                "quarantined": sum(s["quarantined"] for s in summary.values()),
            },
            "quarantine_file": str(QUARANTINE.relative_to(ROOT)),
            "quarantine_cumulative": len(ledger),
            "rules": [
                "All inline content is copied verbatim from work/sources/_api_cache, "
                "work/sources clones, or deterministic raw GitHub fetches cached in "
                "work/hydration_cache/ (git-ignored); nothing is fabricated.",
                "Rows with <50 chars inline code or <100 chars prose are moved, with their "
                "full original body, to the quarantine ledger, not invented.",
            ],
        }
        write_json(guard_wave1(WAVE1 / "reports_wave1" / "hydration_report.json"), payload)
        _write_log(payload)
        print(f"[hydrate] totals before={payload['totals']['before']} "
              f"hydrated={payload['totals']['hydrated']} "
              f"quarantined={payload['totals']['quarantined']}")


def _write_log(payload: dict) -> None:
    lines = ["# Wave-1 hydration log", "", f"Generated: {payload['generated_at']}", ""]
    lines.append("All inline content is verbatim from local caches/clones or cached raw GitHub fetches. No fabrication.")
    lines.append("")
    lines.append("| Family | before | hydrated | quarantined |")
    lines.append("|---|---:|---:|---:|")
    for fam, s in payload["families"].items():
        lines.append(f"| `{fam}` | {s['before']} | {s['hydrated']} | {s['quarantined']} |")
    t = payload["totals"]
    lines.append(f"| **TOTAL** | **{t['before']}** | **{t['hydrated']}** | **{t['quarantined']}** |")
    lines.append("")
    LOG.parent.mkdir(parents=True, exist_ok=True)
    LOG.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
