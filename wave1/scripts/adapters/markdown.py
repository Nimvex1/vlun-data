"""markdown.py - Wave-1 `markdown_two_revision` -> severity derivation.

METADATA ONLY.  This adapter reads the already-admitted Markdown and GHSA
metadata and derives the owned severity_reconciliation family from them.

Family contract (wave1/00_governance/label_domains.json):
  * severity_reconciliation = severity labels ONLY ({high, low}).  Markdown's
    `quality.invariants` and GHSA's `label` are genuine severity labels and
    belong here; they must NEVER be written into G_patch_verification or
    J_verified_patch.
  * G and J are no longer emitted by this adapter at all.
  * Each severity row additionally carries `vulnerable_commit` / `fixed_commit`
    when the report records an audited revision SHA in its permalink and a
    distinct fix SHA, so a downstream prove-candidate builder can find the pair.
    This adapter never writes prove_candidates.jsonl (mitigation.py owns it).
  * invariants.jsonl, candidates and admitted layers are owned by other
    writers and are never touched here.

Idempotent: the family file is rewritten from admitted data on every run.

Usage: python wave1/scripts/adapters/markdown.py
"""
from __future__ import annotations

import re
import sys
from collections import Counter
from pathlib import Path

# _common.py lives in wave1/scripts/, this file in wave1/scripts/adapters/
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _common import (  # noqa: E402
    WAVE1,
    guard_wave1,
    read_jsonl,
    utc_now,
    write_json,
    write_jsonl,
)
from ghsa import build_reference_index, stratified_split, upgrade_ghsa_row  # noqa: E402

SOURCE = "markdown_two_revision"
MD_ADMIT = WAVE1 / "04_admitted" / "markdown_two_revision" / "findings.jsonl"
GH_ADMIT = WAVE1 / "04_admitted" / "ghsa_web3_netnew" / "findings.jsonl"
BENCH_SEVERITY = WAVE1 / "benchmark_wave1" / "severity_reconciliation.jsonl"
REPORT_PATH = WAVE1 / "reports_wave1" / "markdown_harvest.json"

SEVERITY_LABELS = {"high", "low"}

_SHA40 = re.compile(r"[0-9a-fA-F]{40}\Z")
# The audited/initial commit is the git revision the report was recorded at,
# embedded in its GitHub permalink (blob/commit/tree/<40hex>).
_PERMALINK_SHA = re.compile(r"/(?:blob|commit|tree)/([0-9a-fA-F]{40})\b", re.I)


def is_sha40(value: object) -> bool:
    return _SHA40.fullmatch(str(value or "")) is not None


def audited_commit_from_permalink(permalink: object) -> str:
    """Return the audited/initial 40-hex commit recorded in a report permalink."""
    m = _PERMALINK_SHA.search(str(permalink or ""))
    return m.group(1).lower() if m else ""


def distinct_commit_pair(row: dict) -> dict:
    """Return {vulnerable_commit, fixed_commit} for a real two-revision pair.

    The vulnerable/audited SHA comes from the report permalink, the fixed SHA
    from the report's recorded fix_commit.  Both must be 40-hex and different.
    No pair is returned when either side is missing, invalid or identical.
    """
    vuln = str(row.get("vulnerable_commit") or "").lower()
    fix = str(row.get("fixed_commit") or row.get("fix_commit") or "").lower()
    if not (is_sha40(vuln) and is_sha40(fix)) or vuln == fix:
        return {}
    return {"vulnerable_commit": vuln, "fixed_commit": fix}


def _dist(rows: list[dict], field: str) -> dict[str, int]:
    return dict(sorted(Counter(str(r.get(field)) for r in rows).items()))


def _load_severity_rows() -> tuple[list[dict], Counter, Counter]:
    """Return (normalized severity rows, per-source counts)."""
    out: list[dict] = []
    counts: Counter = Counter()

    for r in read_jsonl(guard_wave1(MD_ADMIT)):
        lab = str((r.get("quality") or {}).get("invariants") or "").lower()
        row = {
            "candidate_id": r["candidate_id"],
            "source": r.get("source", SOURCE),
            "repo_slug": r.get("repo_slug", ""),
            "label": lab,
            "fix_commit": r.get("fix_commit", ""),
            "permalink": r.get("permalink", ""),
            "group": "firm:" + str(r.get("firm") or r.get("repo_slug") or "unknown"),
        }
        # Preserve a real two-revision pair on the derived row so downstream
        # prove-candidate builders can discover it (mitigation.py owns the
        # prove_candidates.jsonl pool; this adapter never writes to it).
        audited = audited_commit_from_permalink(r.get("permalink"))
        row.update(distinct_commit_pair({
            "vulnerable_commit": audited,
            "fixed_commit": r.get("fix_commit"),
        }))
        out.append(row)
        counts["markdown"] += 1

    index = build_reference_index()
    upgrades: Counter = Counter()
    for r in read_jsonl(guard_wave1(GH_ADMIT)):
        lab = str(r.get("label") or (r.get("quality") or {}).get("invariants") or "").lower()
        resolved, status = upgrade_ghsa_row(r, index)
        upgrades[status] += 1
        row = {
            "candidate_id": r["candidate_id"],
            "source": r.get("source", "ghsa_web3_netnew"),
            "repo_slug": r.get("repo_slug", ""),
            "label": lab,
            "fix_commit": resolved.get("fix_commit", ""),
            "permalink": r.get("permalink", ""),
            "group": "repo:" + str(r.get("repo_slug") or "unknown"),
        }
        if resolved.get("pr_number") is not None:
            row["pr_number"] = resolved["pr_number"]
        # GHSA permalinks are advisory pages, not revisioned blobs; only a
        # permalink-recorded audited SHA plus a distinct fix SHA yields a pair.
        audited = audited_commit_from_permalink(r.get("permalink"))
        row.update(distinct_commit_pair({
            "vulnerable_commit": audited,
            "fixed_commit": resolved.get("fix_commit"),
        }))
        out.append(row)
        counts["ghsa"] += 1
    return out, counts, upgrades


def main() -> None:
    rows, source_counts, upgrades = _load_severity_rows()
    bad = sorted({r["label"] for r in rows} - SEVERITY_LABELS)
    if bad:
        raise ValueError(f"severity_reconciliation would carry non-severity labels: {bad}")

    splits = stratified_split(rows, lambda r: r["group"], lambda r: r["label"])
    sev_rows: list[dict] = []
    distinct_pair_rows = 0
    for r in rows:
        lab = r["label"]
        split = splits[r["candidate_id"]]
        pair = distinct_commit_pair(r)
        if pair:
            distinct_pair_rows += 1
        sev_rows.append({
            "task_id": f"severity::{split}::{r['candidate_id']}",
            "candidate_id": r["candidate_id"],
            "label": lab,
            "answer": lab,
            "split": split,
            "repo_slug": r["repo_slug"],
            "source": r["source"],
            "fix_commit": r["fix_commit"],
            "permalink": r["permalink"],
            **({"pr_number": r["pr_number"]} if "pr_number" in r else {}),
            **pair,
        })

    write_jsonl(guard_wave1(BENCH_SEVERITY), sev_rows)

    split_labels = {
        s: dict(sorted(Counter(r["label"] for r in sev_rows if r["split"] == s).items()))
        for s in ("train", "val", "test")
    }
    report = {
        "built_at": utc_now(),
        "source": SOURCE,
        "repos_attempted": 0,
        "repos_ok": 0,
        "files_scanned": 0,
        "items_found": len(rows),
        "collisions": 0,
        "admitted": len(rows),
        "admitted_by_label": _dist(rows, "label"),
        "admitted_by_source": dict(sorted(source_counts.items())),
        "api_calls_used": 0,
        "api_failures": [],
        "severity_reconciliation_rows": len(sev_rows),
        "severity_rows_with_distinct_commit_pair": distinct_pair_rows,
        "prove_candidates_rows_written": 0,
        "severity_label_distribution": _dist(sev_rows, "label"),
        "severity_split_distribution": _dist(sev_rows, "split"),
        "severity_split_label_distribution": split_labels,
        "ghsa_reference_upgrades": dict(sorted(upgrades.items())),
        "split_method": "deterministic sha256(firm/repo|candidate_id) 70/15/15, stratified by firm/repo",
        "benchmark_rows_written": {"severity_reconciliation.jsonl": len(sev_rows)},
        "notes": [
            "METADATA_ONLY: this adapter no longer harvests; it derives from admitted metadata only.",
            "This adapter STOPPED emitting G_patch_verification and J_verified_patch. Markdown/GHSA "
            "severity labels high/low are legitimate only in severity_reconciliation and must never "
            "be admitted into the patch-verification domain.",
            f"Two-revision provenance: {distinct_pair_rows} severity rows carry BOTH "
            "vulnerable_commit (audited revision from the report permalink) and fixed_commit "
            "(distinct recorded fix SHA). Rows lacking a real audited SHA or a distinct fix SHA "
            "carry neither field. This adapter does NOT add rows to prove_candidates.jsonl - "
            "mitigation.py owns that NOT_SCORABLE pool.",
            "invariants.jsonl is owned by another writer and is never written by this adapter.",
            "Both severity labels are asserted present in validation and test; the deterministic "
            "firm/repo stratification keeps the split reproducible across reruns.",
            "Idempotent derivation: the family file is rewritten from admitted data; no "
            "candidate/admitted/invariants/PRESENT/network writes occur here.",
        ],
    }
    write_json(guard_wave1(REPORT_PATH), report)
    print(f"[markdown] severity_reconciliation={len(sev_rows)} labels={report['severity_label_distribution']} "
          f"splits={report['severity_split_distribution']} "
          f"distinct_commit_pairs={distinct_pair_rows}")
    print(f"[markdown] split_labels={split_labels}")


if __name__ == "__main__":
    main()
