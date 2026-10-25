#!/usr/bin/env python3
"""Score the F-extension: per-axis rejection-evidence metrics and duplicate-radar metrics.

The scorer is deliberately strict about three things:

* an axis or pair is only scored where the gold label is assessable, and a missing
  prediction is a miss for the gold class - never a skipped row;
* malformed predictions are invalid: they are never coerced to `unknown`, and they
  are counted as a miss for the gold class, so garbage cannot raise a score by
  leaving the denominator; the invalid counts are reported separately;
* the frequency-learning baselines are fitted on the TRAIN split only and then
  evaluated separately on validation and test, so no number here was selected
  after looking at test labels.

F-A scoring
-----------
One decision per (row, assessed axis). Gold and prediction are three-class
(`supported` / `not_supported` / `unknown`). For each axis a 3x3 confusion matrix
is reported and every class gets one-vs-rest

    TP = gold == pred == class
    FP = pred == class and gold != class
    FN = gold == class and (pred != class or prediction missing)

Missing predictions are in the FN of their gold class and in the coverage
denominator; an invalid prediction is counted the same way (a miss for the gold
class) and is reported in the invalid statistics. Precision is TP/(TP+FP), recall
TP/(TP+FN) and per-class support is the gold count inside the evaluated set.
Per-axis accuracy is correct/evaluated over the assessed axes; the denominator
is published. The reported aggregates are:

    micro_accuracy  = sum of correct decisions / sum of evaluated decisions
                      (pooled over the assessed axes, never over rows x axes twice)
    macro_accuracy  = unweighted mean of the per-axis accuracies
    macro_f1        = unweighted mean of the per-axis macro-F1 values, where a
                      per-axis macro-F1 is the mean over classes that occur in
                      that axis's gold (classes with zero support are excluded,
                      not scored as zero)

Axis groups are reported separately. `input_observable` axes are answered by
reading a field out of the packet (a public status, a pointer, a recorded attempt
status); `reasoning` axes need a substantive judgement; the `meta` axis is the
`unknown_or_insufficient_evidence` synthesis. A headline over the observable axes
is not evidence of triage judgement and is never merged into the reasoning
aggregate.

`technical_explanation_axes` is scored separately: exact-set match over rows
where every technical axis is assessable, plus multi-label precision/recall/F1.
The multi-label numbers are micro-averaged over every (row, technical axis) cell:
TP = the axis is in gold and in the prediction, FP = predicted and not gold,
FN = gold and not predicted. Rows with a missing or malformed field are counted
as such and excluded from the multilabel cells.

F-B scoring
-----------
One decision per pair over `same_vulnerability` / `distinct_vulnerability` /
`ambiguous`, with the same one-vs-rest definitions and a full 3x3 confusion
matrix. A missing prediction is a FN for the gold class and lowers coverage; a
malformed prediction is invalid and is counted as a miss for the gold class.

Pairs share candidate submissions and canonical findings, so a per-row Wilson
interval would be invalid. Confidence intervals come from a deterministic
cluster bootstrap over candidate submissions (`source.candidate_record_id`),
with a fixed seed. When the cluster count is below `MIN_BOOTSTRAP_CLUSTERS` the
scorer reports the count and the limitation instead of inventing an interval.
The pool spans five audits, so even the cluster interval is conditional on those
audits; that limitation is carried in the output.

Predictions are one JSON object per line:
    {"task_id": "Fa::...", "axes": {"<axis>": "supported|not_supported|unknown"},
     "technical_explanation_axes": ["<axis>", ...]}
    {"task_id": "Fb::...", "relationship": "same_vulnerability|distinct_vulnerability|ambiguous"}

Run with `--baselines` to publish the train-fitted frequency baselines and the
fixed diagnostics, with `--check` to verify the published file, and with
`--predictions FILE` to score a model run.
"""
from __future__ import annotations

import argparse
import collections
import json
import math
import random
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
ANSWERS = ("supported", "not_supported", "unknown")
RELATIONS = ("same_vulnerability", "distinct_vulnerability", "ambiguous")

TECHNICAL_AXES = (
    "reason_attributed_to_judge_or_sponsor",
    "reason_supported_by_cited_code",
    "exploit_attempted_and_claimed_violation_not_demonstrated",
)
# Input-observable: the packet carries the field, so copying it is not triage.
# Reasoning: the axis requires a judgement the packet does not contain.
# Meta: the synthesis axis that records insufficient public evidence.
AXIS_GROUPS = {
    "input_observable": (
        "rejection_status_publicly_reported",
        "claim_corroborated_as_duplicate_of_confirmed_finding",
        "exploit_attempted_and_claimed_violation_not_demonstrated",
    ),
    "reasoning": (
        "reason_attributed_to_judge_or_sponsor",
        "reason_supported_by_cited_code",
    ),
    "meta": ("unknown_or_insufficient_evidence",),
}

# Deterministic cluster bootstrap. The unit is the candidate submission: pairs
# share candidates and canonical findings, and resampling rows (or findings)
# would duplicate the same evidence inside a resample. The pool has five audits,
# so an audit-level interval is not defensible and is not published.
BOOTSTRAP_SEED = 20240517
BOOTSTRAP_RESAMPLES = 1000
MIN_BOOTSTRAP_CLUSTERS = 10
BOOTSTRAP_UNIT = "candidate_submission"


def _rows(path: Path) -> list[dict]:
    return read_jsonl(path) if path.exists() else []


def _scorable(task: dict) -> bool:
    return task.get("answer_key_status", "labeled") in ("labeled", "partial")


def _class_scores(support: int, tp: int, fp: int, fn: int) -> dict:
    """One-vs-rest metrics with explicit zero-denominator behaviour.

    A class absent from the evaluated gold has support 0 and no F1; it is excluded
    from macro averages. A class with support but no prediction of that class has
    precision 0 and F1 0, not `None`.
    """
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / support if support else None
    if support == 0:
        f1 = None
    elif tp == 0:
        f1 = 0.0
    else:
        f1 = 2 * precision * recall / (precision + recall)
    return {
        "support": support,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 4) if precision is not None else None,
        "recall": round(recall, 4) if recall is not None else None,
        "f1": round(f1, 4) if f1 is not None else None,
    }


def _macro_f1(per_class: dict[str, dict]) -> float | None:
    values = [scores["f1"] for scores in per_class.values() if scores["f1"] is not None]
    # fsum, not sum(): exactly rounded and version-stable across the
    # supported CPython matrix (3.12 changed builtin sum() accuracy).
    return round(math.fsum(values) / len(values), 4) if values else None


def _confusion_counts(confusion: collections.Counter, labels: tuple[str, ...],
                      missing: collections.Counter,
                      invalid: collections.Counter | None = None) -> tuple[dict, int, int]:
    """Per-class one-vs-rest counts plus accuracy inputs from a confusion matrix.

    `missing` holds gold classes for decisions without a prediction: they are FN
    for the gold class and part of the accuracy/recall denominator. A prediction
    whose label is outside the vocabulary is a wrong answer, not a skipped one:
    it is counted the same way, so garbage cannot raise the score by leaving the
    denominator.
    """
    invalid = invalid or collections.Counter()
    per_class: dict[str, dict] = {}
    correct = 0
    evaluated = sum(confusion.values()) + sum(missing.values()) + sum(invalid.values())
    for gold in labels:
        support = (sum(confusion[(gold, pred)] for pred in labels)
                   + missing[gold] + invalid[gold])
        tp = confusion[(gold, gold)]
        fp = sum(confusion[(other, gold)] for other in labels if other != gold)
        fn = support - tp
        per_class[gold] = _class_scores(support, tp, fp, fn)
        correct += tp
    return per_class, correct, evaluated


def _full_matrix(confusion: collections.Counter, labels: tuple[str, ...]) -> dict:
    return {f"{gold}->{pred}": confusion[(gold, pred)]
            for gold in labels for pred in labels}


# ---------------------------------------------------------------------------
# F-A
# ---------------------------------------------------------------------------
def _fa_axis_block(axis: str, confusion: collections.Counter,
                   missing: collections.Counter, invalid: collections.Counter) -> dict:
    per_class, correct, evaluated = _confusion_counts(confusion, ANSWERS, missing, invalid)
    return {
        "axis": axis,
        "group": next((group for group, axes in AXIS_GROUPS.items() if axis in axes),
                      "ungrouped"),
        "assessed_decisions": evaluated,
        "valid_predictions": sum(confusion.values()),
        "missing_predictions": sum(missing.values()),
        "invalid_predictions": invalid,
        "evaluated": evaluated,
        "correct": correct,
        "accuracy": round(correct / evaluated, 4) if evaluated else None,
        "macro_f1": _macro_f1(per_class),
        "confusion": _full_matrix(confusion, ANSWERS),
        "per_class": per_class,
    }


def _fa_aggregate(axes_block: dict[str, dict], axes: tuple[str, ...]) -> dict:
    """Aggregate over a set of axes.

    micro accuracy pools decisions over axes; macro values are unweighted means of
    the per-axis values. Invalid predictions are outside both denominators.
    """
    blocks = [axes_block[axis] for axis in axes if axis in axes_block]
    evaluated = sum(b["evaluated"] for b in blocks)
    correct = sum(b["correct"] for b in blocks)
    accuracies = [b["accuracy"] for b in blocks if b["evaluated"]]
    f1s = [b["macro_f1"] for b in blocks if b["macro_f1"] is not None]
    return {
        "axes": list(axes),
        "axis_decisions": sum(b["assessed_decisions"] for b in blocks),
        "evaluated_decisions": evaluated,
        "correct_decisions": correct,
        "micro_accuracy": round(correct / evaluated, 4) if evaluated else None,
        # fsum, not sum(): version-stable float aggregation (see _macro_f1).
        "macro_accuracy": round(math.fsum(accuracies) / len(accuracies), 4) if accuracies else None,
        "macro_f1": round(math.fsum(f1s) / len(f1s), 4) if f1s else None,
    }


def score_fa(tasks: list[dict], predict: dict[str, dict], name: str,
             split: str | None = None) -> dict:
    """Score three-class axis decisions on the axes the packet can carry."""
    selected = [t for t in tasks if _scorable(t) and (
        split is None or t.get("split") == split)]
    excluded_unlabeled = sum(1 for t in tasks if not _scorable(t) and (
        split is None or t.get("split") == split))

    confusion: dict[str, collections.Counter] = {axis: collections.Counter() for axis in AXES}
    missing: dict[str, collections.Counter] = {axis: collections.Counter() for axis in AXES}
    invalid: dict[str, collections.Counter] = {axis: collections.Counter() for axis in AXES}

    expected = valid = missing_total = invalid_total = 0
    rows_without_prediction = rows_invalid_prediction = 0
    predictions_on_unassessed = 0
    technical = collections.Counter()
    multilabel: dict[str, collections.Counter] = {
        axis: collections.Counter() for axis in AXES}

    for task in selected:
        assessed = [axis for axis in (task.get("assessed_axes") or []) if axis in AXES]
        gold_axes = (task.get("answer_key") or {}).get("axes") or {}
        given = predict.get(task["id"])
        if given is None:
            rows_without_prediction += 1
            predicted_axes: dict = {}
            row_invalid = False
        elif not isinstance(given, dict):
            rows_invalid_prediction += 1
            predicted_axes = {}
            row_invalid = True
        else:
            predicted_axes = given.get("axes")
            row_invalid = not isinstance(predicted_axes, dict)
            if row_invalid:
                rows_invalid_prediction += 1
                predicted_axes = {}
        for axis in predicted_axes:
            if axis in AXES and axis not in assessed:
                predictions_on_unassessed += 1
        for axis in assessed:
            gold = gold_axes.get(axis)
            if gold not in ANSWERS:
                raise ValueError(f"{task['id']} gold for {axis} is {gold!r}")
            expected += 1
            if row_invalid:
                invalid[axis][gold] += 1
                invalid_total += 1
                continue
            if axis not in predicted_axes:
                missing[axis][gold] += 1
                missing_total += 1
                continue
            value = predicted_axes[axis]
            if value not in ANSWERS:
                invalid[axis][gold] += 1
                invalid_total += 1
                continue
            valid += 1
            confusion[axis][(gold, value)] += 1

        # The technical field is only comparable where all three technical axes
        # were assessable, so an unassessable axis cannot be scored as an omission.
        if not all(axis in assessed for axis in TECHNICAL_AXES):
            technical["not_evaluable"] += 1
            continue
        gold_technical = (task.get("answer_key") or {}).get("technical_explanation_axes") or []
        if any(axis not in AXES for axis in gold_technical):
            raise ValueError(f"{task['id']} gold technical axes outside the vocabulary")
        raw = given.get("technical_explanation_axes") if isinstance(given, dict) else None
        if raw is None:
            technical["missing"] += 1
            continue
        if not isinstance(raw, list) or any(not isinstance(a, str) for a in raw):
            technical["invalid"] += 1
            continue
        if any(a not in AXES for a in raw):
            technical["invalid"] += 1
            continue
        technical["evaluable"] += 1
        gold_set, pred_set = set(gold_technical), set(raw)
        technical["exact_match"] += int(gold_set == pred_set)
        technical["status_as_technical"] += int(AXES[0] in pred_set)
        technical["duplicate_as_technical"] += int(AXES[3] in pred_set)
        for axis in TECHNICAL_AXES:
            in_gold, in_pred = axis in gold_set, axis in pred_set
            multilabel[axis]["gold"] += int(in_gold)
            multilabel[axis]["predicted"] += int(in_pred)
            multilabel[axis]["tp"] += int(in_gold and in_pred)
            multilabel[axis]["fp"] += int(in_pred and not in_gold)
            multilabel[axis]["fn"] += int(in_gold and not in_pred)

    per_axis = {axis: _fa_axis_block(axis, confusion[axis], missing[axis], invalid[axis])
                for axis in AXES}
    groups = {group: _fa_aggregate(per_axis, axes) for group, axes in AXIS_GROUPS.items()}
    groups["all"] = _fa_aggregate(per_axis, AXES)

    ml_tp = sum(multilabel[a]["tp"] for a in TECHNICAL_AXES)
    ml_fp = sum(multilabel[a]["fp"] for a in TECHNICAL_AXES)
    ml_fn = sum(multilabel[a]["fn"] for a in TECHNICAL_AXES)
    ml_per_axis = {}
    for axis in TECHNICAL_AXES:
        ml_per_axis[axis] = _class_scores(
            multilabel[axis]["gold"], multilabel[axis]["tp"],
            multilabel[axis]["fp"], multilabel[axis]["fn"])

    return {
        "predictor": name,
        "split": split or "all",
        "rows_scored": len(selected),
        "rows_unlabeled_excluded": excluded_unlabeled,
        "rows_without_prediction": rows_without_prediction,
        "rows_invalid_prediction": rows_invalid_prediction,
        "axis_decisions": expected,
        "predictions_on_unassessed_axes": predictions_on_unassessed,
        "coverage": {
            "axis_decisions_expected": expected,
            "valid_predictions": valid,
            "missing_predictions": missing_total,
            "invalid_predictions": invalid_total,
            "prediction_coverage": round(valid / expected, 4) if expected else None,
            "answered_rate": (round((valid + invalid_total) / expected, 4)
                              if expected else None),
            "invalid_rate": round(invalid_total / expected, 4) if expected else None,
            "denominator_note": ("coverage counts decisions on assessed axes only; a missing "
                                 "prediction and an invalid prediction are both a miss "
                                 "for the gold class and stay in the denominator"),
        },
        "micro_accuracy": groups["all"]["micro_accuracy"],
        "macro_accuracy": groups["all"]["macro_accuracy"],
        "macro_f1": groups["all"]["macro_f1"],
        "aggregates": groups,
        "per_axis": per_axis,
        "technical_explanation_field": {
            "evaluable_rows": technical["evaluable"],
            "not_evaluable_rows": technical["not_evaluable"],
            "missing_field_rows": technical["missing"],
            "invalid_field_rows": technical["invalid"],
            "exact_match_rate": (round(technical["exact_match"] / technical["evaluable"], 4)
                                 if technical["evaluable"] else None),
            "answered_status_as_technical": technical["status_as_technical"],
            "answered_duplicate_as_technical": technical["duplicate_as_technical"],
            "multilabel_aggregation": (
                "micro over every (row, technical axis) cell of rows with a valid "
                "field and all technical axes assessable"),
            "multilabel": {
                "tp": ml_tp, "fp": ml_fp, "fn": ml_fn,
                "precision": round(ml_tp / (ml_tp + ml_fp), 4) if (ml_tp + ml_fp) else None,
                "recall": round(ml_tp / (ml_tp + ml_fn), 4) if (ml_tp + ml_fn) else None,
                "f1": (round(2 * ml_tp / (2 * ml_tp + ml_fp + ml_fn), 4)
                       if (2 * ml_tp + ml_fp + ml_fn) else None),
                "per_axis": ml_per_axis,
            },
        },
    }


# ---------------------------------------------------------------------------
# F-B
# ---------------------------------------------------------------------------
def _fb_counts(tasks: list[dict], predict: dict[str, dict]) -> tuple:
    confusion: collections.Counter = collections.Counter()
    missing: collections.Counter = collections.Counter()
    invalid: collections.Counter = collections.Counter()
    rows_without_prediction = rows_invalid_prediction = 0
    for task in tasks:
        gold = (task.get("answer_key") or {}).get("relationship")
        if gold not in RELATIONS:
            raise ValueError(f"{task.get('id')} gold relationship is {gold!r}")
        given = predict.get(task["id"])
        if given is None:
            rows_without_prediction += 1
            missing[gold] += 1
            continue
        if not isinstance(given, dict) or "relationship" not in given:
            rows_invalid_prediction += 1
            invalid[gold] += 1
            continue
        predicted = given.get("relationship")
        if predicted not in RELATIONS:
            rows_invalid_prediction += 1
            invalid[gold] += 1
            continue
        confusion[(gold, predicted)] += 1
    return (confusion, missing, invalid, rows_without_prediction, rows_invalid_prediction)


def _fb_metrics(confusion: collections.Counter, missing: collections.Counter,
                invalid: collections.Counter) -> dict:
    per_class, correct, evaluated = _confusion_counts(confusion, RELATIONS, missing, invalid)
    return {
        "per_class": per_class,
        "correct": correct,
        "evaluated": evaluated,
        "accuracy": round(correct / evaluated, 4) if evaluated else None,
        "macro_f1": _macro_f1(per_class),
        "invalid_predictions": sum(invalid.values()),
        "missing_predictions": sum(missing.values()),
    }


def _percentile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    if not ordered:
        raise ValueError("no bootstrap values")
    position = q * (len(ordered) - 1)
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] + fraction * (ordered[upper] - ordered[lower])


def cluster_bootstrap(tasks: list[dict], predict: dict[str, dict],
                      seed: int = BOOTSTRAP_SEED,
                      resamples: int = BOOTSTRAP_RESAMPLES) -> dict:
    """Percentile interval over candidate-submission clusters.

    The resampling unit is `source.candidate_record_id`: a pair's two sides and a
    candidate's several pairs are correlated, so rows are not independent. The
    seed and the number of resamples are constants of this script, which makes two
    runs byte-identical. The pool covers few audits, so the interval is conditional
    on those audits and is not an audit-level generalisation.
    """
    clusters: dict[str, list[dict]] = collections.defaultdict(list)
    for task in tasks:
        clusters[(task.get("source") or {}).get("candidate_record_id")
                 or task.get("id")].append(task)
    names = sorted(clusters)
    audits = sorted({name.split("/")[0] for name in names})
    base = _fb_metrics(*_fb_counts(tasks, predict)[:3]) if tasks else {
        "accuracy": None, "macro_f1": None}
    if len(names) < MIN_BOOTSTRAP_CLUSTERS:
        return {
            "available": False,
            "unit": BOOTSTRAP_UNIT,
            "seed": seed,
            "clusters": len(names),
            "audits": len(audits),
            "rows": len(tasks),
            "macro_f1": base["macro_f1"],
            "accuracy": base["accuracy"],
            "limitation": (f"{len(names)} candidate-submission clusters is below the "
                           f"{MIN_BOOTSTRAP_CLUSTERS} needed for a defensible interval; "
                           "counts are reported instead"),
        }
    rng = random.Random(seed)
    accuracies: list[float] = []
    f1s: list[float] = []
    for _ in range(resamples):
        sample: list[dict] = []
        for _ in range(len(names)):
            sample.extend(clusters[names[rng.randrange(len(names))]])
        metrics = _fb_metrics(*_fb_counts(sample, predict)[:3])
        if metrics["accuracy"] is not None:
            accuracies.append(metrics["accuracy"])
        if metrics["macro_f1"] is not None:
            f1s.append(metrics["macro_f1"])
    return {
        "available": True,
        "unit": BOOTSTRAP_UNIT,
        "seed": seed,
        "resamples": resamples,
        "clusters": len(names),
        "audits": len(audits),
        "accuracy": base["accuracy"],
        "accuracy_95ci": ([round(_percentile(accuracies, 0.025), 4),
                           round(_percentile(accuracies, 0.975), 4)]
                          if accuracies else None),
        "macro_f1": base["macro_f1"],
        "macro_f1_95ci": ([round(_percentile(f1s, 0.025), 4),
                           round(_percentile(f1s, 0.975), 4)] if f1s else None),
        "limitation": (f"{len(audits)} audits back these clusters; the interval resamples "
                       "submissions within those audits and does not generalise to unseen "
                       "audit projects"),
    }


def score_fb(tasks: list[dict], predict: dict[str, dict], name: str,
             split: str | None = None, cohort: str | None = None,
             bootstrap: bool = True) -> dict:
    """Score the three-class pair decision with class-specific TP/FP/FN."""
    selected = []
    for task in tasks:
        if task.get("answer_key_status", "labeled") != "labeled":
            continue
        if split is not None and task.get("split") != split:
            continue
        if cohort is not None:
            provenance = (task.get("answer_key") or {}).get("label_provenance") or {}
            if provenance.get("cohort") != cohort:
                continue
        selected.append(task)

    confusion, missing, invalid, rows_missing, rows_invalid = _fb_counts(selected, predict)
    metrics = _fb_metrics(confusion, missing, invalid)
    by_hardness: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    by_audit: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    by_cohort: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    for task in selected:
        gold = task["answer_key"]["relationship"]
        given = predict.get(task["id"])
        predicted = given.get("relationship") if isinstance(given, dict) else None
        outcome = "missing" if given is None else (
            "invalid" if predicted not in RELATIONS else ("correct"
                                                          if predicted == gold else "wrong"))
        hardness = task["answer_key"].get("hardness") or "not_applicable"
        by_hardness[hardness][outcome] += 1
        by_audit[(task.get("source") or {}).get("candidate_record_id", "?").split("/")[0]][
            outcome] += 1
        provenance = (task.get("answer_key") or {}).get("label_provenance") or {}
        by_cohort[provenance.get("cohort") or "unrecorded"][outcome] += 1

    def _breakdown(groups: dict[str, collections.Counter]) -> dict:
        out = {}
        for label, counter in sorted(groups.items()):
            total = sum(counter.values())
            out[label] = {
                "correct": counter["correct"],
                "wrong": counter["wrong"],
                "missing": counter["missing"],
                "invalid": counter["invalid"],
                "total": total,
                "accuracy": (round(counter["correct"] / total, 4) if total else None),
            }
        return out

    evaluated = metrics["evaluated"]
    expected = len(selected)
    result = {
        "predictor": name,
        "split": split or "all",
        "cohort": cohort or "all",
        "pairs_scored": expected,
        "evaluated_pairs": evaluated,
        "rows_without_prediction": rows_missing,
        "rows_invalid_prediction": rows_invalid,
        "coverage": {
            "expected": expected,
            "valid_predictions": sum(confusion.values()),
            "missing_predictions": metrics["missing_predictions"],
            "invalid_predictions": metrics["invalid_predictions"],
            "prediction_coverage": (round(sum(confusion.values()) / expected, 4)
                                    if expected else None),
            "answered_rate": (round((sum(confusion.values()) + metrics["invalid_predictions"])
                                    / expected, 4) if expected else None),
            "denominator_note": ("missing predictions and invalid predictions are both a "
                                 "miss for the gold class and reduce coverage; invalid "
                                 "counts are reported separately"),
        },
        "accuracy": metrics["accuracy"],
        "macro_f1": metrics["macro_f1"],
        "confusion": _full_matrix(confusion, RELATIONS),
        "confusion_observed": {f"{g}->{p}": n for (g, p), n in sorted(confusion.items()) if n},
        "missing_by_gold": {label: missing[label] for label in RELATIONS},
        "invalid_by_gold": {label: invalid[label] for label in RELATIONS},
        "per_class": metrics["per_class"],
        "by_hardness": _breakdown(by_hardness),
        "by_project": _breakdown(by_audit),
        "by_label_cohort": _breakdown(by_cohort),
        "note": ("ambiguous is a scored class: predicting a decision where the evidence "
                 "does not establish one is an error, never skipped; miss/malformed "
                 "predictions are reported in coverage"),
    }
    if bootstrap:
        result["cluster_bootstrap"] = cluster_bootstrap(selected, predict)
    return result


# ---------------------------------------------------------------------------
# Baselines: frequency predictors are fitted on TRAIN only
# ---------------------------------------------------------------------------
def _fit_rows(tasks: list[dict], fit_split: str = "train") -> list[dict]:
    return [t for t in tasks if t.get("split") == fit_split and _scorable(t)]


def frequency_baseline(tasks: list[dict], kind: str,
                       fit_split: str = "train") -> tuple[dict[str, dict], dict]:
    """Fit a majority predictor on `fit_split` and return predictions for every row.

    The fit never sees validation or test labels. Ties are broken by the canonical
    answer order, so the result is deterministic.
    """
    fitted = _fit_rows(tasks, fit_split)
    predictions: dict[str, dict] = {}
    fitted_counts: dict[str, dict] = {}
    if kind == "majority_axis":
        winners: dict[str, str] = {}
        for axis in AXES:
            counter = collections.Counter()
            for task in fitted:
                if axis in (task.get("assessed_axes") or []):
                    counter[task["answer_key"]["axes"][axis]] += 1
            winners[axis] = next(
                (label for label in ANSWERS if counter[label] == counter.most_common(1)[0][1]),
                "unknown") if counter else "unknown"
            fitted_counts[axis] = {label: counter[label] for label in ANSWERS}
        for task in tasks:
            predictions[task["id"]] = {
                "axes": {axis: winners[axis]
                         for axis in (task.get("assessed_axes") or [])},
                "technical_explanation_axes": []}
    elif kind == "majority_pair":
        counter = collections.Counter(
            task["answer_key"]["relationship"] for task in fitted)
        winner = next((label for label in RELATIONS
                       if counter[label] == counter.most_common(1)[0][1]), "ambiguous") \
            if counter else "ambiguous"
        fitted_counts = {"relationship": {label: counter[label] for label in RELATIONS},
                         "winner": winner}
        for task in tasks:
            predictions[task["id"]] = {"relationship": winner}
    else:
        raise ValueError(f"no frequency baseline named {kind!r}")
    return predictions, {
        "fit_split": fit_split,
        "fit_rows": len(fitted),
        "fitted_counts": fitted_counts,
    }


def baseline_predictions(tasks: list[dict], kind: str,
                         fit_split: str = "train") -> dict[str, dict]:
    """Fixed diagnostics or a train-fitted frequency predictor.

    `all_supported`, `all_unknown`, `always_duplicate`, `never_duplicate` and
    `always_ambiguous` are fixed diagnostics: they are reported but never used to
    pick a floor. `majority_axis` / `majority_pair` are fitted on `fit_split`.
    """
    if kind in ("majority_axis", "majority_pair"):
        return frequency_baseline(tasks, kind, fit_split)[0]
    out: dict[str, dict] = {}
    if kind == "all_supported":
        for task in tasks:
            out[task["id"]] = {
                "axes": {axis: "supported"
                         for axis in (task.get("assessed_axes") or [])},
                "technical_explanation_axes": list(AXES)}
    elif kind == "all_unknown":
        for task in tasks:
            out[task["id"]] = {
                "axes": {axis: "unknown"
                         for axis in (task.get("assessed_axes") or [])},
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
    else:
        raise ValueError(f"unknown baseline {kind!r}")
    return out


def _fa_by_split(tasks: list[dict], predictions: dict[str, dict], name: str) -> dict:
    return {split: score_fa(tasks, predictions, name, split=split)
            for split in ("train", "validation", "test")}


def _fb_by_split(tasks: list[dict], predictions: dict[str, dict], name: str) -> dict:
    return {split: score_fb(tasks, predictions, name, split=split)
            for split in ("train", "validation", "test")}


def _reference_floor(by_split: dict[str, dict]) -> dict:
    """Pre-register the validation score of the train-fitted frequency predictor.

    Test is reported but never used to select a floor: picking the maximum over
    predictors after seeing test labels is exactly the leak this replaces.
    """
    validation = by_split.get("validation") or {}
    return {
        "selected_on": "validation",
        "predictor": "majority_axis" if "macro_accuracy" in validation
        else "majority_pair",
        "micro_accuracy": validation.get("micro_accuracy", validation.get("accuracy")),
        "macro_f1": validation.get("macro_f1"),
        "test_reported_not_used_for_selection": {
            "micro_accuracy": (by_split.get("test") or {}).get(
                "micro_accuracy", (by_split.get("test") or {}).get("accuracy")),
            "macro_f1": (by_split.get("test") or {}).get("macro_f1"),
        },
        "note": ("the train-fitted frequency predictor is the reference floor; fixed "
                 "predictors are diagnostics and no maximum over predictors is "
                 "published"),
    }


def build_baseline_payload(fa: list[dict], fb: list[dict]) -> dict:
    fa_freq_preds, fa_fit = frequency_baseline(fa, "majority_axis")
    fb_freq_preds, fb_fit = frequency_baseline(fb, "majority_pair")
    fa_freq_by_split = _fa_by_split(fa, fa_freq_preds, "majority_axis")
    fb_freq_by_split = _fb_by_split(fb, fb_freq_preds, "majority_pair")
    fa_fixed = []
    for kind in ("all_supported", "all_unknown"):
        fa_fixed.append({
            "predictor": kind,
            "role": "diagnostic (not a floor)",
            "by_split": _fa_by_split(fa, baseline_predictions(fa, kind), kind),
        })
    fb_fixed = []
    for kind in ("always_duplicate", "never_duplicate", "always_ambiguous"):
        fb_fixed.append({
            "predictor": kind,
            "role": "diagnostic (not a floor)",
            "by_split": _fb_by_split(fb, baseline_predictions(fb, kind), kind),
        })
    primary_predictions = fb_freq_preds
    return {
        "generated_by": "scripts/score_f_extension.py",
        "methodology": {
            "frequency_baseline": (
                "the majority class per axis (F-A) and per relationship (F-B) is fitted "
                "on TRAIN rows only, then evaluated on train, validation and test with "
                "the split denominators reported"),
            "fixed_predictors": (
                "all_supported, all_unknown, always_duplicate, never_duplicate and "
                "always_ambiguous are fixed diagnostics; they are not used to select a "
                "floor"),
            "reference_floor": (
                "the train-fitted frequency predictor's validation score; the test "
                "score is reported but was not used to choose anything"),
            "cluster_bootstrap": {
                "unit": BOOTSTRAP_UNIT,
                "seed": BOOTSTRAP_SEED,
                "resamples": BOOTSTRAP_RESAMPLES,
                "min_clusters": MIN_BOOTSTRAP_CLUSTERS,
                "limitation": ("the pair pool covers five audits, so the interval "
                               "resamples submissions inside those audits and does "
                               "not generalise to unseen projects"),
            },
        },
        "fa": {
            "tasks": len(fa),
            "by_split": dict(collections.Counter(t.get("split") for t in fa)),
            "frequency_baseline": {
                "predictor": "majority_axis",
                **fa_fit,
                "by_split": fa_freq_by_split,
            },
            "fixed_diagnostics": fa_fixed,
            "reference_floor": _reference_floor(fa_freq_by_split),
        },
        "fb": {
            "tasks": len(fb),
            "by_split": dict(collections.Counter(t.get("split") for t in fb)),
            "cohorts": dict(collections.Counter(
                ((t.get("answer_key") or {}).get("label_provenance") or {}).get("cohort")
                for t in fb)),
            "frequency_baseline": {
                "predictor": "majority_pair",
                **fb_fit,
                "by_split": fb_freq_by_split,
            },
            "fixed_diagnostics": fb_fixed,
            "reference_floor": _reference_floor(fb_freq_by_split),
            "primary_cohort": score_fb(fb, primary_predictions, "majority_pair",
                                       cohort="primary"),
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--predictions", help="JSONL of model predictions for either family")
    ap.add_argument("--baselines", action="store_true",
                    help="compute and publish the train-fitted baselines")
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
        payload = build_baseline_payload(fa, fb)
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
            log("wrote baselines: F-A train-fitted majority validation "
                f"micro accuracy {payload['fa']['reference_floor']['micro_accuracy']}, "
                f"F-B train-fitted majority validation accuracy "
                f"{payload['fb']['reference_floor']['micro_accuracy']}")
        return 0

    predictions = [json.loads(line) for line in
                   Path(args.predictions).read_text(encoding="utf-8").splitlines()
                   if line.strip()] if args.predictions else []
    if not predictions:
        log("no predictions supplied: use --predictions FILE or --baselines")
        return 2
    indexed = {p["task_id"]: p for p in predictions}
    results = {
        "generated_by": "scripts/score_f_extension.py",
        "predictions_file": Path(args.predictions).name,
        "fa": score_fa(fa, indexed, "model"),
        "fa_by_split": _fa_by_split(fa, indexed, "model"),
        "fb": score_fb(fb, indexed, "model"),
        "fb_by_split": _fb_by_split(fb, indexed, "model"),
        "fb_primary_cohort": score_fb(fb, indexed, "model", cohort="primary"),
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
