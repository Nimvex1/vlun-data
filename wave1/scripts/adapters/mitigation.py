"""mitigation.py -- Wave-1 C4 Mitigation Reviews -> benchmark derivation.

METADATA_ONLY governance (wave1/00_governance/rights.jsonl, source_id
c4_mitigation): NEVER vendor issue/comment prose.  This adapter only reads the
already-admitted metadata rows and derives owned benchmark families from them.

Family contract (wave1/00_governance/label_domains.json):
  * G_patch_verification  = patch_verification_outcome labels ONLY, one row per
    admitted C4 mitigation row (all 531, irrespective of whether a fix commit
    was found).  A missing fix commit is itself evidence, not a reason to drop
    the row; the outcome_label is the supervision signal.
  * J_verified_patch      = OWNED BY run_wave1_experiments.py.  This adapter no
    longer writes or truncates it; only genuinely executed two-revision L6 rows
    belong there.  Unexecuted patch diffs belong in G, not J.
  * prove_candidates      = NOT_SCORABLE pool, no answer/label fields.  Only rows
    that carry BOTH a 40-hex vulnerable SHA and a 40-hex fix SHA, that are
    STRICTLY DIFFERENT, and that carry a real permalink/source ref.  Rows whose
    two SHAs are identical are dropped here (they remain as single-SHA records
    in 04_admitted/c4_mitigation/findings.jsonl).

This module writes ONLY its owned paths (G, prove_candidates, its report).
J_verified_patch.jsonl is owned by run_wave1_experiments.py and is left untouched
here.  It never writes the harvest/candidate/admitted layers and never makes
network calls, so reruns are idempotent.

Usage: python wave1/scripts/adapters/mitigation.py
"""
from __future__ import annotations

import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

# _common.py lives at wave1/scripts/_common.py
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from _common import (  # noqa: E402
    WAVE1,
    guard_wave1,
    read_jsonl,
    sha256_text,
    utc_now,
    write_json,
    write_jsonl,
)

SOURCE = "c4_mitigation"
ADMITTED = WAVE1 / "04_admitted" / "c4_mitigation" / "findings.jsonl"
BENCH_G = WAVE1 / "benchmark_wave1" / "G_patch_verification.jsonl"
BENCH_J = WAVE1 / "benchmark_wave1" / "J_verified_patch.jsonl"
BENCH_PROVE = WAVE1 / "benchmark_wave1" / "prove_candidates.jsonl"
REPORT = WAVE1 / "reports_wave1" / "mitigation_harvest.json"

CONFIRMED = "mitigation_confirmed"
UNMITIGATED = "unmitigated_or_regression"
G_LABELS = {CONFIRMED, UNMITIGATED}

# The SHAs on admitted mitigation rows were extracted from the issue body by
# _commits() (structural heuristics), so this is their honest provenance.
MITIGATION_SHA_BASIS = "mitigation_issue_text"

J_EMPTY_NOTE = (
    "J_verified_patch is empty because no wave1 row carries an executed two-revision "
    "L6 artefact (violation reproduced on vulnerable SHA + blocked on fixed SHA). "
    "J stays empty until real execution is performed; unexecuted patch diffs belong in G."
)

_SHA40 = re.compile(r"[0-9a-fA-F]{40}\Z")
_PERMALINK = re.compile(r"https?://[^\s/]+/\S+", re.I)


def is_sha40(value: object) -> bool:
    s = str(value or "")
    return _SHA40.fullmatch(s) is not None


def has_provenance(row: dict) -> bool:
    """A real permalink/source ref, not an empty or placeholder value."""
    for key in ("permalink", "issue_url", "source_ref"):
        val = str(row.get(key) or "").strip()
        if val and _PERMALINK.match(val):
            return True
    return False


def stratified_split(rows: list[dict], group_fn, label_fn) -> dict[str, str]:
    """Deterministic contest-stratified 70/15/15 split.

    Rows are grouped by contest (repo_slug), ordered inside each contest by a
    deterministic hash anchored on the contest slug, then allocated 70/15/15
    within the contest.  This keeps every contest represented in each split
    while still landing near the global 70/15/15 target.  Finally, if either
    validation or test is missing a label that exists globally, the
    lexicographically-smallest-hash donor row of that label is moved there from
    train (or, failing that, from the other non-target split).
    """
    groups: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        groups[str(group_fn(r))].append(r)

    assign: dict[str, str] = {}
    for group in sorted(groups):
        grp = sorted(
            groups[group],
            key=lambda r: (sha256_text(group + "|" + r["candidate_id"]), r["candidate_id"]),
        )
        n = len(grp)
        if n >= 3:
            n_train = max(0, min(round(n * 0.70), n - 2))
            n_val = max(1, min(round(n * 0.15), n - n_train - 1))
        else:
            n_train, n_val = (1 if n >= 1 else 0), 0
        for i, r in enumerate(grp):
            cid = r["candidate_id"]
            assign[cid] = "train" if i < n_train else ("val" if i < n_train + n_val else "test")

    all_labels = {label_fn(r) for r in rows}
    for target in ("val", "test"):
        held = {label_fn(r) for r in rows if assign[r["candidate_id"]] == target}
        for lab in sorted(all_labels - held):
            pool = [
                r for r in rows
                if label_fn(r) == lab and assign[r["candidate_id"]] == "train"
            ] or [
                r for r in rows
                if label_fn(r) == lab and assign[r["candidate_id"]] not in (target, "train")
            ]
            if pool:
                donor = min(pool, key=lambda r: sha256_text(r["candidate_id"]))
                assign[donor["candidate_id"]] = target
    return assign


def _dist(rows: list[dict], field: str) -> dict[str, int]:
    return dict(sorted(Counter(str(r.get(field)) for r in rows).items()))


def main() -> None:
    now = utc_now()
    rows = [r for r in read_jsonl(guard_wave1(ADMITTED))]

    bad_labels = sorted({str(r.get("outcome_label")) for r in rows} - G_LABELS)
    if bad_labels:
        raise ValueError(f"G would admit labels outside patch_verification_outcome: {bad_labels}")

    splits = stratified_split(rows, lambda r: r["repo_slug"], lambda r: r["outcome_label"])

    # ---- G: all admitted mitigation rows, supervision = outcome_label --------
    g_rows: list[dict] = []
    for r in rows:
        lab = r["outcome_label"]
        split = splits[r["candidate_id"]]
        g_rows.append({
            "task_id": f"G::{split}::{r['candidate_id']}",
            "candidate_id": r["candidate_id"],
            "label": lab,
            "answer": lab,
            "split": split,
            "repo_slug": r["repo_slug"],
            "source": r.get("source", SOURCE),
        })

    # ---- J: owned by run_wave1_experiments.py; NOT emitted here -------------
    # Kept as an empty local only for the report count; never written to disk.
    j_rows: list[dict] = []

    # ---- prove_candidates: NOT_SCORABLE, no answer/label ---------------------
    # Strict filter: both SHAs must be 40-hex, must be DIFFERENT, and the row
    # must carry a real permalink/source ref.  Equal-SHA rows are dropped from
    # this pool but are untouched in the admitted layer.
    prove_rows: list[dict] = []
    dropped_equal_sha = 0
    dropped_invalid_sha = 0
    dropped_no_provenance = 0
    seen: set[str] = set()
    for r in rows:
        vuln, fix = r.get("vulnerable_commit"), r.get("fixed_commit")
        if not (is_sha40(vuln) and is_sha40(fix)):
            dropped_invalid_sha += 1
            continue
        v_sha, f_sha = str(vuln).lower(), str(fix).lower()
        if v_sha == f_sha:
            dropped_equal_sha += 1
            continue
        if not has_provenance(r):
            dropped_no_provenance += 1
            continue
        cid = r["candidate_id"]
        if cid in seen:  # defensive: rewrite-from-admitted must not duplicate
            continue
        seen.add(cid)
        prove_rows.append({
            "candidate_id": cid,
            "vuln_sha": v_sha,
            "fix_sha": f_sha,
            "repo_slug": r["repo_slug"],
            "source": r.get("source", SOURCE),
            "permalink": r["permalink"],
            "fix_commit_basis": r.get("fix_commit_basis") or MITIGATION_SHA_BASIS,
            "distinct_revisions": True,
        })

    write_jsonl(guard_wave1(BENCH_G), g_rows)
    # J_verified_patch.jsonl is deliberately NOT written here: the wave-1
    # experiment runner is its single writer (genuine L6 artefacts only).
    write_jsonl(guard_wave1(BENCH_PROVE), prove_rows)

    g_split_labels = {
        s: dict(sorted(Counter(
            r["label"] for r in g_rows if r["split"] == s
        ).items()))
        for s in ("train", "val", "test")
    }
    report = {
        "generated_at": now,
        "source": SOURCE,
        "admitted": len(rows),
        "admitted_by_label": _dist(rows, "outcome_label"),
        "benchmark_G_rows": len(g_rows),
        "benchmark_J_rows": len(j_rows),
        "prove_candidates_rows": len(prove_rows),
        "prove_candidates_distinct_revisions": sum(1 for r in prove_rows if r["distinct_revisions"]),
        "prove_candidates_identical_sha_pairs": sum(1 for r in prove_rows if not r["distinct_revisions"]),
        "dropped_equal_sha": dropped_equal_sha,
        "dropped_invalid_sha": dropped_invalid_sha,
        "dropped_no_provenance": dropped_no_provenance,
        "G_label_distribution": _dist(g_rows, "label"),
        "G_split_distribution": _dist(g_rows, "split"),
        "G_split_label_distribution": g_split_labels,
        "split_method": "deterministic sha256(repo_slug|candidate_id) contest-stratified 70/15/15",
        "notes": [
            "G is derived from ALL admitted C4 mitigation rows; outcome_label is the only "
            "supervision signal. Severity strings high/low are NEVER admitted into G.",
            J_EMPTY_NOTE,
            f"prove_candidates rows={len(prove_rows)}: a NOT_SCORABLE pool with no answer and no "
            "label fields. A row qualifies only if BOTH vulnerable_commit and fixed_commit are "
            "40-hex SHAs, they are STRICTLY DIFFERENT, and the row has a real permalink/source ref.",
            f"dropped_equal_sha={dropped_equal_sha}: admitted rows whose vulnerable_commit equals "
            "fixed_commit. They are excluded from prove_candidates but remain unchanged in "
            "04_admitted/c4_mitigation/findings.jsonl as single-SHA records.",
            f"dropped_invalid_sha={dropped_invalid_sha}, dropped_no_provenance={dropped_no_provenance}: "
            "rows failing the 40-hex SHA check or carrying no real permalink/source ref. These three "
            "drop counts plus the kept rows partition the admitted rows.",
            "Idempotent derivation: prove_candidates is rewritten from admitted data on every run "
            "(deduplicated by candidate_id); this module writes no candidate/admitted/invariants/"
            "PRESENT files and makes no network calls.",
        ],
    }
    write_json(guard_wave1(REPORT), report)

    print(f"[mitigation] admitted={len(rows)} G={len(g_rows)} J={len(j_rows)} "
          f"prove_candidates={len(prove_rows)} dropped_equal_sha={dropped_equal_sha} "
          f"dropped_invalid_sha={dropped_invalid_sha} "
          f"dropped_no_provenance={dropped_no_provenance}")
    print(f"[mitigation] G splits={report['G_split_distribution']} "
          f"labels={report['G_split_label_distribution']}")


if __name__ == "__main__":
    main()
