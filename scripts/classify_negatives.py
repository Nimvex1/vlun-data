#!/usr/bin/env python3
"""Report-side view of the canonical rejection-evidence layer.

This script no longer decides anything. `scripts/build_rejection_corpus.py`
derives one record per negative in `derived_rejections/rejection_corpus.jsonl`;
this file reads that layer and emits the aggregates that README.md and the v2.1
quality report consume, so the same six definitions answer the same question in
every report.

Why it changed: the previous version picked a single best class per record and
let a duplicate pointer stand for a technical reason. That produced "331
negatives with a defensible reason", of which 321 were duplicate
corroborations — a count of classifications, not of explanations. The six
metrics below are independent axes and are explicitly not additive.

    python scripts/classify_negatives.py [--check]
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_rejection_corpus as corpus  # noqa: E402
from vlun import REPORTS, log, write_json  # noqa: E402

CORPUS_PATH = corpus.CORPUS
OUT = REPORTS / "negative_verification_stats.json"

# negative_class -> the evidence type that put the record in that class.
CLASS_EVIDENCE_TYPE = {
    "executionally_disproven": "experimentally_verified",
    "experimentally_confirmed_underlying_issue": "experimentally_verified",
    "public_judge_or_sponsor_explanation": "externally_attributed",
    "business_scenario_exclusion": "externally_attributed",
    "code_derived_blocker": "derived_fact",
    "corroborated_duplicate": "derived_fact",
    "duplicate_label_unresolved_pointer": "observed_fact",
    "withdrawn_by_author": "observed_fact",
    "scope_or_eligibility_label": "observed_fact",
    "dispute_or_invalid_label": "observed_fact",
    "unattributed_participant_discussion": "reported_claim",
    "code_gate_context_only": "derived_fact",
    "unresolved": "unknown",
}

# The classes that carry a reason a consumer can act on. `corroborated_duplicate`
# is a reason the copy was redundant, never a reason the claim is false; the
# `carries_technical_reason` field is what separates them.
REASON_BEARING = (
    "executionally_disproven",
    "experimentally_confirmed_underlying_issue",
    "public_judge_or_sponsor_explanation",
    "business_scenario_exclusion",
    "code_derived_blocker",
    "corroborated_duplicate",
)


def corpus_rows() -> list[dict]:
    if not CORPUS_PATH.exists():
        raise SystemExit("run scripts/build_rejection_corpus.py first: "
                         f"{corpus.CORPUS} does not exist")
    return [json.loads(line) for line in
            CORPUS_PATH.read_text(encoding="utf-8").splitlines() if line.strip()]


def view(row: dict) -> dict:
    """The per-record shape downstream consumers (build_subsets.py) read."""
    axes = row["axes"]
    cls = row["primary_reason_class"]
    detail = {
        "attributed": axes["attributed_reason"] if cls in (
            "public_judge_or_sponsor_explanation", "business_scenario_exclusion") else None,
        "code": axes["code_supported_reason"] if cls in (
            "code_derived_blocker", "code_gate_context_only") else None,
        "corroboration": axes["duplicate_corroboration"] if cls == "corroborated_duplicate"
                         else None,
        "labels": row["original_verdict"]["public_labels"] if cls in (
            "withdrawn_by_author", "scope_or_eligibility_label", "dispute_or_invalid_label",
            "duplicate_label_unresolved_pointer") else None,
        "discussion": axes["attributed_reason"]["participant_statements"]
        if cls == "unattributed_participant_discussion" else None,
    }
    return {
        "finding_id": row["finding_id"],
        "repository": row["repository"],
        "original_verdict": row["original_verdict"]["status"],
        "original_duplicate_of": row["original_verdict"]["duplicate_of"],
        "duplicate": row["original_verdict"]["duplicate"],
        "negative_class": cls,
        "reason_classes": row["reason_classes"],
        "class_evidence": {"evidence_type": CLASS_EVIDENCE_TYPE[cls],
                           "detail": {k: v for k, v in detail.items() if v is not None}},
        "carries_technical_reason": bool(row["technical_verification"]
                                         ["counts_as_technical_reason_for_why_the_claim_is_false"]),
        "technical_bases": row["technical_verification"]["bases"],
        "corroboration": {k: axes["duplicate_corroboration"][k] for k in
                          ("methods", "best_confidence", "corroborated", "explicit_pointer",
                           "is_technical_explanation", "reading")},
        "executed_disproof": axes["exploit_attempt"]["experiment"],
        "is_false_positive": row["is_false_positive"],
        "is_false_positive_basis": row["is_false_positive_basis"],
        "confidence": row["confidence"],
        "metrics": row["metrics"],
    }


def build() -> dict:
    rows = [view(r) for r in corpus_rows()]
    by_class = collections.Counter(r["negative_class"] for r in rows)
    blockers = collections.Counter(
        (("none" if r["negative_class"] == "executionally_disproven" else
          (r["executed_disproof"] or {}).get("status", "not_attempted")
          if r["executed_disproof"] else "not_attempted"))
        for r in rows)
    stats = {
        "generated_by": "scripts/classify_negatives.py (reads derived_rejections/"
                        "rejection_corpus.jsonl; it derives nothing itself)",
        "definitions_version": corpus.DEFINITIONS_VERSION,
        "corpus_schema_version": corpus.SCHEMA_VERSION,
        "total": len(rows),
        "by_class": dict(by_class),
        "class_vocabulary": list(corpus.REASON_CLASSES),
        "primary_precedence": list(corpus.PRIMARY_ORDER),
        "reason_bearing_classes": list(REASON_BEARING),
        "metrics": _metric_totals(rows),
        "metric_definitions": corpus.DEFINITIONS,
        "is_false_positive": dict(collections.Counter(str(r["is_false_positive"])
                                                      for r in rows)),
        "blocking_reason": dict(blockers),
        "executed_negative_experiments": dict(collections.Counter(
            (r["executed_disproof"] or {}).get("status") or "unknown"
            for r in rows if r["executed_disproof"])),
        "corroborated_by_confirmed_finding": _metric(rows, "explicit_pointer"),
        "corroborated_by_any_accepted_finding": sum(
            1 for r in rows if r["metrics"]
            ["claim_corroborated_as_duplicate_of_confirmed_finding"]),
        "attributed_by_named_source": sum(1 for r in rows if r["metrics"]
                                          ["reason_attributed_to_judge_or_sponsor"]),
        "experimentally_verified": sum(1 for r in rows if r["negative_class"]
                                       == "executionally_disproven"),
        "code_derived_technical_reasons": sum(1 for r in rows if r["negative_class"]
                                              == "code_derived_blocker"),
        "technical_reason_why_the_claim_is_false": sum(1 for r in rows
                                                       if r["carries_technical_reason"]),
        "guarantee": (
            "Counts are independent axes, not a sum. A `corroborated_duplicate` record is "
            "explicitly NOT a false positive and NOT a technical explanation: the claim was "
            "accepted elsewhere in the same audit and only this copy was redundant. A code "
            "gate counts only when it removes the standing the submission's own text claims. "
            "`unknown` is a valid outcome and is never replaced with an invented reason. The "
            "original contest verdict is carried verbatim and never overwritten."),
        "known_ceiling": {
            "largest_cluster": "2024-04-noya AccountingManager / connector functions",
            "blocker": "rpc_unavailable",
            "detail": ("the NOYA test fixtures create a mainnet fork in `setUp()`; without an "
                       "archive endpoint (`VLUN_RPC_URL`) no exploit attempt can be executed "
                       "against those contracts, so those negatives stay `unknown` rather than "
                       "being given an invented reason"),
        },
        "records": rows,
    }
    return stats


def _metric_totals(rows: list[dict]) -> dict:
    keys = list(corpus.METRICS)
    return {k: sum(1 for r in rows if r["metrics"][k]) for k in keys}


def _metric(rows: list[dict], field: str) -> int:
    return sum(1 for r in rows
               if r["metrics"]["claim_corroborated_as_duplicate_of_confirmed_finding"]
               and r["corroboration"][field])


def render(stats: dict) -> str:
    m = stats["metrics"]
    lines = ["# Negative (rejected) evidence summary\n",
             f"Generated by `scripts/classify_negatives.py` from "
             f"`derived_rejections/rejection_corpus.jsonl` "
             f"(`{stats['corpus_schema_version']}`, definitions "
             f"`{stats['definitions_version']}`).\n",
             f"Records: **{stats['total']}**. Each axis below counts independently; they are "
             "not additive.\n",
             "| axis | records |", "|---|---|"]
    for k, v in m.items():
        lines.append(f"| `{k}` | {v} |")
    lines.append(f"\n**Technical reason why the claim is false: "
                 f"{stats['technical_reason_why_the_claim_is_false']} of {stats['total']}.** "
                 "Duplicate corroboration, public labels and unresolved pointers are excluded "
                 "from that number by definition.\n")
    lines.append(f"Primary reason class: `{json.dumps(stats['by_class'], sort_keys=True)}`\n")
    lines.append("The definitions and the precedence order live in "
                 "`derived_rejections/definitions.json`; the prose explanation is "
                 "`reports/rejection_evidence.md`.\n")
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out-stats", default=str(OUT))
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    stats = build()
    text = json.dumps(stats, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    md = render(stats)
    md_path = REPORTS / "negative_verification.md"
    if args.check:
        stale = [p for p, t in [(Path(args.out_stats), text), (md_path, md)]
                 if not Path(p).exists() or Path(p).read_text(encoding="utf-8") != t]
        if stale:
            log("STALE: " + ", ".join(str(s) for s in stale))
            return 1
        log("negative_verification_stats.json is current")
        return 0
    write_json(Path(args.out_stats), json.loads(text))
    md_path.write_text(md, encoding="utf-8", newline="\n")
    log(f"negative_verification_stats.json: {json.dumps(stats['by_class'], sort_keys=True)}")
    log(f"  metrics={json.dumps(stats['metrics'], sort_keys=True)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
