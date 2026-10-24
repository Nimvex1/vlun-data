#!/usr/bin/env python3
"""Score the F-extension: per-axis rejection-evidence metrics and duplicate-radar metrics.

Two things this refuses to do:

* score an axis on a row whose packet cannot carry that axis (the row is excluded
  from that axis's denominator instead of being counted as a miss);
* let a model bank accuracy by guessing the majority class - the published
  per-axis and per-pair baselines are computed by this same script, so a headline
  number that does not beat them is not a result.

Predictions are one JSON object per line:
    {"task_id": "Fa::...", "axes": {"<axis>": "supported|not_supported|unknown"},
     "technical_explanation_axes": ["<axis>", ...]}
    {"task_id": "Fb::...", "relationship": "same_vulnerability|distinct_vulnerability|ambiguous"}

Run with `--baselines` to publish the trivial predictors, and with
`--predictions FILE` to score a model run.
"""
from __future__ import annotations

import argparse
import collections
import json
import math
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

from vlun import BENCH, REPORTS, log, read_jsonl, write_json  # noqa: E402

FA_FILE = BENCH / "Fa_rejection_evidence_axis_vector.jsonl"
FB_FILE = BENCH / "Fb_duplicate_radar_pair.jsonl"
OUT_BASELINES = REPORTS / "f_extension_baselines.json"
OUT_RESULTS = REPORTS / "f_extension_evaluation.json"

AXES = (
    "rejection_status_publicly_reported",
    "reason_attributed_to_judge_or_sponsor",
    "reason_supported_by_cited_code",
    "claim_corroborated_as_duplicate_of_confirmed_finding",
    "exploit_attempted_and_claimed_violation_not_demonstrated",
    "unknown_or_insufficient_evidence",
)
RELATIONS = ("same_vulnerability", "distinct_vulnerability", "ambiguous")


def _rows(path: Path) -> list[dict]:
    return read_jsonl(path) if path.exists() else []


def wilson_interval(hits: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval: a small per-axis sample must not read as precision."""
    if total == 0:
        return (0.0, 0.0)
    p = hits / total
    denominator = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denominator
    margin = (z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total))) / denominator
    return (round(max(0.0, centre - margin), 4), round(min(1.0, centre + margin), 4))


def prf(scores: collections.Counter, label: str) -> dict:
    tp = scores[(label, "tp")]
    fp = scores[(label, "fp")]
    fn = scores[(label, "fn")]
    support = scores[(label, "support")]
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    f1 = (2 * precision * recall / (precision + recall)
          if precision and recall else (1.0 if precision == recall == 1.0 else 0.0))
    return {"support": support, "tp": tp, "fp": fp, "fn": fn,
            "precision": round(precision, 4) if precision is not None else None,
            "recall": round(recall, 4) if recall is not None else None,
            "f1": round(f1, 4),
            "accuracy": round(tp / support, 4) if support else None,
            "accuracy_95ci": list(wilson_interval(tp, support))}


def score_fa(tasks: list[dict], predict: dict[str, dict], name: str) -> dict:
    """Per-axis scoring over the rows where that axis is assessable."""
    scores: collections.Counter = collections.Counter()
    coverage = collections.Counter()
    answered = 0
    conflation = collections.Counter()
    for task in tasks:
        if task["answer_key_status"] not in ("labeled", "partial"):
            continue
        given = predict.get(task["id"])
        if given is None:
            continue
        answered += 1
        assessed = set(task["assessed_axes"])
        gold_axes = task["answer_key"]["axes"]
        predicted_axes = given.get("axes") or {}
        for axis in AXES:
            if axis not in assessed:
                continue
            coverage[axis] += 1
            gold = gold_axes[axis]
            predicted = predicted_axes.get(axis)
            scores[(axis, "support")] += 1
            if predicted == gold:
                scores[(axis, "tp")] += 1
            elif predicted is not None:
                scores[(axis, "fp")] += 1
            else:
                scores[(axis, "fn")] += 1
        gold_technical = set(task["answer_key"]["technical_explanation_axes"])
        predicted_technical = set(given.get("technical_explanation_axes") or [])
        conflation["technical_exact"] += int(gold_technical == predicted_technical)
        # The trap this family exists for: calling a duplicate or a bare status a
        # technical explanation of why the claim is false.
        conflation["status_as_technical"] += int(AXES[0] in predicted_technical)
        conflation["duplicate_as_technical"] += int(AXES[3] in predicted_technical)
        conflation["rows"] += 1
    per_axis = {axis: prf(scores, axis) for axis in AXES}
    assessable = sum(coverage.values())
    correct = sum(per_axis[axis]["tp"] for axis in AXES)
    return {
        "predictor": name,
        "rows_scored": answered,
        "axis_decisions": assessable,
        "axis_accuracy": round(correct / assessable, 4) if assessable else None,
        "per_axis": per_axis,
        "technical_explanation_field": {
            "exact_match_rate": round(
                conflation["technical_exact"] / conflation["rows"], 4)
            if conflation["rows"] else None,
            "answered_status_as_technical": conflation["status_as_technical"],
            "answered_duplicate_as_technical": conflation["duplicate_as_technical"],
        },
    }


def score_fb(tasks: list[dict], predict: dict[str, dict], name: str) -> dict:
    confusion = collections.Counter()
    by_hardness = collections.defaultdict(collections.Counter)
    by_audit = collections.defaultdict(collections.Counter)
    scored = 0
    for task in tasks:
        if task["answer_key_status"] != "labeled":
            continue
        given = predict.get(task["id"])
        if given is None:
            continue
        scored += 1
        gold = task["answer_key"]["relationship"]
        predicted = given.get("relationship")
        confusion[(gold, predicted)] += 1
        hardness = task["answer_key"].get("hardness") or "not_applicable"
        by_hardness[hardness][predicted == gold] += 1
        by_audit[task["source"]["candidate_record_id"].split("/")[0]][predicted == gold] += 1
    labels = list(RELATIONS)
    per_class = {}
    totals: collections.Counter = collections.Counter()
    for gold in labels:
        for predicted in labels:
            n = confusion[(gold, predicted)]
            totals[(gold, "support")] += n
            if gold == predicted:
                totals[(gold, "tp")] += n
            elif predicted in labels:
                totals[(gold, "fp")] += n
            # A miss against the gold class is a false negative for that class, and
            # an ambiguous prediction counts as a miss when the gold is a decision.
            if predicted != gold:
                totals[(gold, "fn")] += n
    correct = sum(confusion[(label, label)] for label in labels)
    return {
        "predictor": name,
        "pairs_scored": scored,
        "accuracy": round(correct / scored, 4) if scored else None,
        "accuracy_95ci": list(wilson_interval(correct, scored)),
        "confusion": {f"{gold}->{predicted}": n for (gold, predicted), n in
                      sorted(confusion.items()) if n},
        "per_class": {label: prf(totals, label) for label in labels},
        "by_hardness": {hardness: {"correct": yes[True], "total": sum(yes.values()),
                                   "accuracy": round(yes[True] / sum(yes.values()), 4)}
                        for hardness, yes in sorted(by_hardness.items())},
        "by_project": {audit: {"correct": yes[True], "total": sum(yes.values()),
                               "accuracy": round(yes[True] / sum(yes.values()), 4)}
                       for audit, yes in sorted(by_audit.items())},
        "note": ("ambiguous is a scored class: predicting a decision where the evidence "
                 "does not establish one is counted as an error, never skipped"),
    }


def baseline_predictions(tasks: list[dict], kind: str) -> dict[str, dict]:
    out: dict[str, dict] = {}
    if kind == "majority_axis":
        # Per axis, the class that is most common in the gold answers.
        winners = {}
        for axis in AXES:
            counter = collections.Counter()
            for task in tasks:
                if axis in task["assessed_axes"]:
                    counter[task["answer_key"]["axes"][axis]] += 1
            winners[axis] = counter.most_common(1)[0][0] if counter else "unknown"
        for task in tasks:
            out[task["id"]] = {"axes": {axis: winners[axis] for axis in task["assessed_axes"]},
                               "technical_explanation_axes": []}
    elif kind == "all_supported":
        for task in tasks:
            out[task["id"]] = {"axes": {axis: "supported" for axis in task["assessed_axes"]},
                               "technical_explanation_axes": list(AXES)}
    elif kind == "all_unknown":
        for task in tasks:
            out[task["id"]] = {"axes": {axis: "unknown" for axis in task["assessed_axes"]},
                               "technical_explanation_axes": []}
    elif kind == "always_duplicate":
        for task in tasks:
            out[task["id"]] = {"relationship": "same_vulnerability"}
    elif kind == "never_duplicate":
        for task in tasks:
            out[task["id"]] = {"relationship": "distinct_vulnerability"}
    elif kind == "always_ambiguous":
        for task in tasks:
            out[task["id"]] = {"relationship": "ambiguous"}
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--predictions", help="JSONL of model predictions for either family")
    ap.add_argument("--baselines", action="store_true",
                    help="compute and publish the trivial predictors")
    ap.add_argument("--check", action="store_true",
                    help="verify the published baseline file matches a fresh run")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    fa = _rows(FA_FILE)
    fb = _rows(FB_FILE)
    if not fa and not fb:
        log("no F-extension tasks: nothing to score")
        return 2

    if args.baselines or args.check:
        fa_baselines = [score_fa(fa, baseline_predictions(fa, kind), kind)
                        for kind in ("majority_axis", "all_supported", "all_unknown")]
        fb_baselines = [score_fb(fb, baseline_predictions(fb, kind), kind)
                        for kind in ("always_duplicate", "never_duplicate", "always_ambiguous")]
        payload = {
            "generated_by": "scripts/score_f_extension.py",
            "fa": {"tasks": len(fa), "rows_scored": len(fa), "baselines": fa_baselines,
                   "floor_axis_accuracy": max(b["axis_accuracy"] or 0 for b in fa_baselines)},
            "fb": {"tasks": len(fb), "rows_scored": len(
                [t for t in fb if t["answer_key_status"] == "labeled"]),
                "baselines": fb_baselines,
                "floor_accuracy": max(b["accuracy"] or 0 for b in fb_baselines)},
            "reading": ("a model result is only a result if it beats the floor on the "
                        "same denominators; the floor is per-axis for F-A and overall "
                        "plus per-class for F-B"),
        }
        if args.check:
            published = json.loads(OUT_BASELINES.read_text(encoding="utf-8")) \
                if OUT_BASELINES.exists() else None
            if published != payload:
                log(f"STALE: {OUT_BASELINES} -- run: python scripts/score_f_extension.py "
                    "--baselines")
                return 1
            if not args.quiet:
                log("ok: F-extension baselines current")
            return 0
        write_json(OUT_BASELINES, payload)
        if not args.quiet:
            log(f"wrote baselines: F-A floor "
                f"{payload['fa']['floor_axis_accuracy']:.4f} axis accuracy, F-B floor "
                f"{payload['fb']['floor_accuracy']:.4f} pair accuracy")
        return 0

    predictions = [json.loads(line) for line in
                   Path(args.predictions).read_text(encoding="utf-8").splitlines() if line.strip()] \
        if args.predictions else []
    if not predictions:
        log("no predictions supplied: use --predictions FILE or --baselines")
        return 2
    indexed = {p["task_id"]: p for p in predictions}
    results = {
        "generated_by": "scripts/score_f_extension.py",
        "predictions_file": Path(args.predictions).name,
        "fa": score_fa(fa, indexed, "model"),
        "fb": score_fb(fb, indexed, "model"),
        "coverage": {
            "fa_rows_predicted": sum(1 for t in fa if t["id"] in indexed),
            "fa_rows_total": len(fa),
            "fb_pairs_predicted": sum(1 for t in fb if t["id"] in indexed),
            "fb_pairs_total": len(fb),
        },
    }
    write_json(OUT_RESULTS, results)
    if not args.quiet:
        log(f"scored {results['coverage']['fa_rows_predicted']} F-A rows and "
            f"{results['coverage']['fb_pairs_predicted']} F-B pairs -> {OUT_RESULTS.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
