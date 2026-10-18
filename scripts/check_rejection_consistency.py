#!/usr/bin/env python3
"""Gate: the rejection-evidence layer must say one thing in every report.

`derived_rejections/rejection_corpus.jsonl` is the canonical record layer for why
458 submissions were rejected. This script re-derives every reported count from
the axes on each record — independently of the builder — and fails if any
document, report or subset restates a number that the records do not support.

The rules encode the distinctions that the earlier reports blurred:

  * a duplicate pointer is corroboration, never a technical reason;
  * `is_false_positive` needs a pointer, a reproduced attack, or an executed
    disproof — not a similarity match;
  * a code gate counts only when it removes the standing the claim asserts, and
    the citation it rests on must name an immutable commit;
  * the contest verdict is carried verbatim, so any drift from `jsonl/` fails.

    python scripts/check_rejection_consistency.py            # report, exit 1 on violation
    python scripts/check_rejection_consistency.py --quiet
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_rejection_corpus as corpus  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SHA40 = re.compile(r"^[0-9a-f]{40}$")


def _rows(path: Path) -> list[dict]:
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def recompute_axes(row: dict) -> dict:
    """The six metrics, re-derived from the axes without trusting `row["metrics"]`."""
    a = row["axes"]
    corr = a["duplicate_corroboration"]
    code = a["code_supported_reason"]
    att = a["attributed_reason"]
    exp = a["exploit_attempt"]
    technical = bool(exp["claimed_violation_not_demonstrated"] or att["technical_refutation"]
                     or code["applies"])
    unresolved = not any([
        exp["claimed_violation_not_demonstrated"], exp["underlying_issue_demonstrated"],
        att["applies"], code["applies"], corr["corroborated"]])
    return {
        "rejection_status_publicly_reported": a["status_publicly_reported"]["applies"],
        "reason_attributed_to_judge_or_sponsor": att["applies"],
        "reason_supported_by_cited_code": bool(code["applies"]),
        "claim_corroborated_as_duplicate_of_confirmed_finding": bool(corr["corroborated"]),
        "exploit_attempted_and_claimed_violation_not_demonstrated":
            bool(exp["claimed_violation_not_demonstrated"]),
        "unknown_or_insufficient_evidence": unresolved,
        "_technical_reason": technical,
    }


def check_row(row: dict, source: dict | None = None) -> list[str]:
    """Violations for a single record. `source` is the jsonl row, when available."""
    bad: list[str] = []
    fid = row.get("finding_id", "?")
    recomputed = recompute_axes(row)
    for k, v in recomputed.items():
        if k.startswith("_"):
            continue
        if bool(row.get("metrics", {}).get(k)) != bool(v):
            bad.append(f"{fid}: metric {k} = {row.get('metrics', {}).get(k)} "
                       f"but the axes give {v}")

    bases = set(row["technical_verification"]["bases"])
    if not bases <= set(corpus.TECHNICAL_BASES):
        bad.append(f"{fid}: technical basis outside the closed set: {sorted(bases)}")
    if bool(bases) != row["technical_verification"][
            "counts_as_technical_reason_for_why_the_claim_is_false"]:
        bad.append(f"{fid}: technical flag disagrees with its bases {sorted(bases)}")
    if bool(bases) != bool(recomputed["_technical_reason"]):
        bad.append(f"{fid}: technical flag disagrees with the axes")
    if row["primary_reason_class"] == "corroborated_duplicate" and bases:
        bad.append(f"{fid}: a duplicate corroboration is reported as a technical reason")

    fp = row.get("is_false_positive")
    exp = row["axes"]["exploit_attempt"]
    explicit = row["axes"]["duplicate_corroboration"]["explicit_pointer"]
    if fp is True and not exp["claimed_violation_not_demonstrated"]:
        bad.append(f"{fid}: is_false_positive True without an executed disproof")
    if fp is False and not (explicit or exp["underlying_issue_demonstrated"]):
        bad.append(f"{fid}: is_false_positive False without an explicit pointer or a "
                   "reproduced attack")

    code = row["axes"]["code_supported_reason"]
    if code["applies"]:
        if row["primary_reason_class"] != "code_derived_blocker":
            bad.append(f"{fid}: a code blocker that applies is not the primary class")
        cit = code["citation"] or {}
        if not SHA40.match(str(cit.get("audited_commit") or "")):
            bad.append(f"{fid}: code blocker cites a mutable revision "
                       f"{cit.get('audited_commit')!r}")
        if code["claim_standing"] != "unprivileged":
            bad.append(f"{fid}: code blocker applied to a claim with standing "
                       f"{code['claim_standing']!r}")
        if code["derived_confidence"] != "high":
            bad.append(f"{fid}: code blocker applied at confidence "
                       f"{code['derived_confidence']!r}")

    classes = row["reason_classes"]
    if any(c not in corpus.REASON_CLASSES for c in classes):
        bad.append(f"{fid}: reason class outside the closed vocabulary: {classes}")
    if len(set(classes)) != len(classes):
        bad.append(f"{fid}: duplicate reason classes: {classes}")
    ordered = [c for c in corpus.PRIMARY_ORDER if c in classes]
    if not ordered or ordered[0] != row["primary_reason_class"]:
        bad.append(f"{fid}: primary class {row['primary_reason_class']!r} ignores the "
                   f"precedence order over {classes}")

    if source is not None:
        v = source.get("validation") or {}
        ov = row["original_verdict"]
        if ov["status"] != v.get("status") or ov["duplicate_of"] != (v.get("duplicate_of") or None):
            bad.append(f"{fid}: original verdict was altered")
        if sorted(ov["all_public_statuses"]) != sorted(
                dict.fromkeys(v.get("all_public_statuses") or [v.get("status")])):
            bad.append(f"{fid}: public statuses were altered")
    return bad


def check(corpus_rows: list[dict], stats: dict, negatives: list[dict] | None = None,
          view: list[dict] | None = None) -> list[str]:
    bad: list[str] = []
    ids = [r["finding_id"] for r in corpus_rows]
    if len(set(ids)) != len(ids):
        bad.append(f"corpus holds {len(ids)} rows with {len(set(ids))} unique ids")
    by_id = {r["finding_id"]: r for r in corpus_rows}
    if negatives is not None:
        src_ids = [(n.get("finding") or {}).get("id") for n in negatives]
        missing = [i for i in src_ids if i not in by_id]
        extra = [i for i in ids if i not in set(src_ids)]
        if missing:
            bad.append(f"{len(missing)} negatives have no corpus row, e.g. {missing[:3]}")
        if extra:
            bad.append(f"{len(extra)} corpus rows match no negative, e.g. {extra[:3]}")
        for n in negatives:
            fid = (n.get("finding") or {}).get("id")
            if fid in by_id:
                bad += check_row(by_id[fid], n)
    else:
        for r in corpus_rows:
            bad += check_row(r)

    for metric in corpus.METRICS:
        recount = sum(1 for r in corpus_rows if r["metrics"][metric])
        if stats.get("metrics", {}).get(metric) != recount:
            bad.append(f"stats metric {metric} = {stats.get('metrics', {}).get(metric)} "
                       f"but the records count {recount}")
    tech = sum(1 for r in corpus_rows
               if r["technical_verification"]["counts_as_technical_reason_for_why_the_claim_is_false"])
    if stats.get("technical_reason_for_why_the_claim_is_false") != tech:
        bad.append(f"stats technical_reason = "
                   f"{stats.get('technical_reason_for_why_the_claim_is_false')} but the records "
                   f"count {tech}")
    if stats.get("total") != len(corpus_rows):
        bad.append(f"stats total = {stats.get('total')} but the corpus has {len(corpus_rows)}")
    by_class: dict[str, int] = {}
    for r in corpus_rows:
        by_class[r["primary_reason_class"]] = by_class.get(r["primary_reason_class"], 0) + 1
    if stats.get("primary_reason_class") != by_class:
        bad.append("stats primary_reason_class disagrees with the records")

    if view is not None:
        # `reports/negative_verification_stats.json` must recount the corpus, and its
        # records must not promote a corroboration into a technical reason.
        if len(view) != len(corpus_rows):
            bad.append(f"negative_verification has {len(view)} records vs corpus "
                       f"{len(corpus_rows)}")
        for v in view:
            src = by_id.get(v["finding_id"])
            if src is None:
                bad.append(f"negative_verification record {v['finding_id']} is not in the corpus")
                continue
            if v["carries_technical_reason"] != src["technical_verification"][
                    "counts_as_technical_reason_for_why_the_claim_is_false"]:
                bad.append(f"{v['finding_id']}: technical flag changed on the way to the report")
            if v["negative_class"] != src["primary_reason_class"]:
                bad.append(f"{v['finding_id']}: class changed on the way to the report")
    return bad


CONFLATION_PHRASES = ("with a defensible reason", "negatives with defensible",
                      "defensible rejection reason")
PROSE_FILES = ("README.md", "NOTICE.md", "docs/RUBRIC.md", "docs/DATASHEET.md",
               "reports/final_quality_report.md", "reports/v2_1_quality_report.md",
               "reports/benchmark_metrics.md")
# CHANGELOG.md is append-only history: the retired count may survive there only inside
# a line that says it was corrected or superseded.
HISTORY_FILE = "CHANGELOG.md"
HISTORY_MARKERS = ("correction", "superseded", "recounted")
TECH_IN_README = re.compile(r"\*\*(\d+)\*\* in total have a technical reason")


def check_prose(root: Path, stats: dict) -> list[str]:
    """Generated prose must use the documented axes, not the retired conflation."""
    bad = []
    for rel in PROSE_FILES:
        p = root / rel
        if not p.exists():
            continue
        text = p.read_text(encoding="utf-8")
        for phrase in CONFLATION_PHRASES:
            if phrase in text:
                bad.append(f"{rel} still says {phrase!r}: a duplicate corroboration is not "
                           "a technical reason")
    hist = root / HISTORY_FILE
    if hist.exists():
        for block in re.split(r"\n\s*\n", hist.read_text(encoding="utf-8")):
            if not any(phrase in block for phrase in CONFLATION_PHRASES):
                continue
            if not any(m in block.lower() for m in HISTORY_MARKERS):
                bad.append(f"{HISTORY_FILE} repeats a retired conflated count without "
                           "marking it corrected: "
                           + " ".join(block.split())[:90])
    readme = (root / "README.md")
    if readme.exists():
        m = TECH_IN_README.search(readme.read_text(encoding="utf-8"))
        if m:
            claimed = int(m.group(1))
            actual = stats["technical_reason_for_why_the_claim_is_false"]
            if claimed != actual:
                bad.append(f"README says {claimed} negatives have a technical reason; the "
                           f"records count {actual}")
        else:
            bad.append("README no longer states the technical-reason count from the corpus")
    return bad


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--corpus", default=str(corpus.CORPUS))
    ap.add_argument("--stats", default=str(corpus.STATS_JSON))
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    corpus_rows = _rows(Path(args.corpus))
    stats = json.loads(Path(args.stats).read_text(encoding="utf-8"))
    negatives_path = ROOT / "jsonl" / "negative_findings.jsonl"
    negatives = _rows(negatives_path) if negatives_path.exists() else None
    nv_path = ROOT / "reports" / "negative_verification_stats.json"
    view = json.loads(nv_path.read_text(encoding="utf-8")).get("records") \
        if nv_path.exists() else None
    bad = check(corpus_rows, stats, negatives, view) + check_prose(ROOT, stats)
    if bad:
        for b in bad[:40]:
            print(f"VIOLATION: {b}")
        print(f"{len(bad)} rejection-evidence violation(s)")
        return 1
    if not args.quiet:
        print(f"rejection evidence consistent: {len(corpus_rows)} records, "
              f"{stats['technical_reason_for_why_the_claim_is_false']} technical reasons, "
              f"metrics {json.dumps(stats['metrics'], sort_keys=True)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
