#!/usr/bin/env python3
"""Canonical benchmark-family status: the single, auditable source of truth
for which family may enter the primary metric.

Until this module existed, the headline set was decided by a hand-written
retirement list plus a directory listing: a family was in the headline
because its name was absent from `EXPLORATORY` and its file was not under
`benchmark/retired_families/`. Nothing in that decision consulted the
evidence. A family could therefore enter the headline without ever having
been checked for leakage, split drift or shortcut domination, and the only
way to demote it was to edit a list.

Here the decision is computed from the data at run time. The validity
measurements are the independent audit's own
(`scripts/independent_benchmark_audit.py`), recomputed live -- not read from
a report, so a stale report cannot promote a family. The rules are:

    PRIMARY      no validity flag, enough rows, at least two labels, and no
                 train-only shortcut that solves the held-out split.
    EXPLORATORY  shipped and scored, but demoted: too few rows, a holdout too
                 small to estimate on, or a single observed label. A
                 single-label family is additionally NOT EVALUABLE for
                 accuracy: its accuracy is null with a stated reason, because
                 one observed label makes any accuracy a restatement of the
                 label distribution.
    INVALID      a validity flag that makes the family unusable as
                 evaluation evidence: the answer leaks into the evidence,
                 the held-out labels never appear in train, the split's
                 label mix drifts from train's, groups or records straddle
                 the split boundary, near-duplicates leak, the task is
                 saturated, or a train-only shortcut solves the held-out
                 split.
    NOT_SCORABLE no exactly-matchable scalar answer key (D generative,
                 H descriptive, Q judge-graded).
    UNKNOWN      a family file on disk that no rule covers. Fail-closed:
                 never primary, always reported.

`UNKNOWN` is the important one. A family added to `benchmark/` tomorrow
without a rule cannot become primary by accident, because "no rule matched"
is not "no problems found".

Nothing here rewrites a benchmark row, a split or an answer key. The rows of
an invalid or exploratory family stay in the dataset and stay scored; only
their eligibility for the primary metric changes.

    python scripts/benchmark_status.py            # print the status table
    python scripts/benchmark_status.py --json     # machine-readable
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import independent_benchmark_audit as audit  # noqa: E402

ROOT = _HERE.parent

STATUS_PRIMARY = "PRIMARY"
STATUS_EXPLORATORY = "EXPLORATORY"
STATUS_INVALID = "INVALID"
STATUS_NOT_SCORABLE = "NOT_SCORABLE"
STATUS_UNKNOWN = "UNKNOWN"

#: Every status, in the order a reader cares about them.
ALL_STATUSES = (STATUS_PRIMARY, STATUS_EXPLORATORY, STATUS_INVALID,
                STATUS_NOT_SCORABLE, STATUS_UNKNOWN)

#: Statuses whose rows may enter the primary metric. Everything else is
#: reported in its own block and never counted in the headline.
PRIMARY_STATUSES = frozenset({STATUS_PRIMARY})

#: Thresholds. Every one of them is a number, not a family name: a family
#: is demoted by its measurements, never by a list entry.
THRESHOLDS = {
    # Minimum scorable rows for a family to carry a headline number.
    "min_primary_rows": 100,
    # Minimum scorable rows for a family to be scorable at all (the audit's
    # own "too_small_to_score" rule).
    "min_scorable_rows": 30,
    # Minimum held-out rows before a shortcut accuracy is believed. Below
    # this the shortcut accuracy is noise, so it is not used to demote.
    "min_shortcut_holdout_rows": 30,
    # A train-only shortcut at or above this accuracy on the held-out split
    # means the task is solved without the model.
    "shortcut_dominance_accuracy": 0.90,
    # Minimum number of observed labels for an accuracy to mean anything.
    "min_labels": 2,
}

#: Flags that make a family INVALID as evaluation evidence.
HARD_FLAGS = {
    "answer_literal_leak":
        "the gold label appears in the model-facing evidence",
    "near_duplicate_leak":
        "held-out rows are near-duplicates of train rows",
    "group_overlap":
        "the same group appears on both sides of the train/test boundary",
    "record_id_overlap":
        "the same record id appears on both sides of the train/test boundary",
    "shared_code":
        "held-out rows reuse a train code block verbatim",
    "held_out_labels_unseen_in_train":
        "held-out labels never occur in train",
    "split_composition_drift":
        "the held-out label mix does not resemble the train mix",
    "saturated":
        "one class covers at least 95% of the scorable rows",
}

#: Flags that demote a family to EXPLORATORY. The family stays shipped and
#: scored; it simply cannot carry a headline number.
SOFT_FLAGS = {
    "single_label":
        "every scorable row carries the same label",
    "too_small_to_score":
        "fewer than 30 scorable rows",
    "holdout_too_small":
        "fewer than 30 held-out rows to estimate on",
}

#: The audit's baselines that are fitted on TRAIN ONLY. A baseline fitted on
#: the held-out rows measures nothing, so it is not a floor.
TRAIN_ONLY_BASELINES = (
    "majority_from_train",
    "random_from_train_space",
    "frequency_from_train",
    "title_retrieval",
    "input_retrieval",
    "source_only_lookup",
)

#: Where family files live, relative to the repository root.
SEARCH_DIRS = ("benchmark", "benchmark/retired_families",
               "Vbeta/benchmark_vbeta")


def discover_family_files() -> dict[str, str]:
    """Map every family file on disk to its repo-relative path.

    This is the fail-closed surface: a file that exists but that no rule
    covers is reported as UNKNOWN rather than being silently skipped.
    """
    out: dict[str, str] = {}
    for rel in SEARCH_DIRS:
        d = ROOT / rel
        if not d.is_dir():
            continue
        for p in sorted(d.glob("*.jsonl")):
            if "manifest" in p.name:
                continue
            out[p.name] = f"{rel}/{p.name}"
    return out


def family_path(family_file: str,
                discovered: dict[str, str] | None = None) -> Path | None:
    """Absolute path of a family file, or None when it does not exist."""
    found = discover_family_files() if discovered is None else discovered
    rel = found.get(family_file)
    if rel is not None:
        return ROOT / rel
    spec = audit.FAMILIES.get(family_file)
    if spec is not None:
        cand = ROOT / spec["dir"] / family_file
        if cand.is_file():
            return cand
    return None


def _shortcut_floor(entry: dict) -> dict:
    """The train-only shortcut floor of one family.

    Only baselines fitted on train count. The audit also reports
    `majority_global_official`, which is fitted on every labelled row
    including the held-out ones; it is a diagnostic of the label
    distribution, not a floor, and it is excluded here on purpose.
    """
    bl = entry.get("baselines_test_split") or {}
    if not isinstance(bl, dict) or "best_shortcut_accuracy" not in bl:
        return {"available": False,
                "reason": "no held-out split to fit a shortcut on"}
    per = {}
    for name in TRAIN_ONLY_BASELINES:
        b = bl.get(name)
        if isinstance(b, dict) and b.get("accuracy") is not None:
            per[name] = b["accuracy"]
    best = max(per.values()) if per else None
    return {
        "available": bool(per),
        "best_train_only_accuracy": best,
        "best_train_only_baseline": (
            sorted(k for k, v in per.items() if v == best)[0]
            if per and best is not None else None),
        "train_only_baselines": dict(sorted(per.items())),
        "heldout_rows": bl.get("test_rows"),
        "fitted_on": "train",
    }


def _flag_reasons(flags: list[str], entry: dict) -> list[str]:
    """One evidence-bearing sentence per flag."""
    out = []
    probe = (entry.get("split_drift") or {}).get("train_majority_probe") or {}
    deg = entry.get("degeneracy") or {}
    for flag in flags:
        if flag == "split_composition_drift":
            out.append(
                f"split_composition_drift: train/test label mix L1 distance "
                f"{probe.get('label_mix_l1_distance')} (>= 0.40)")
        elif flag == "held_out_labels_unseen_in_train":
            out.append(
                f"held_out_labels_unseen_in_train: "
                f"{probe.get('test_labels_absent_from_train')}")
        elif flag == "saturated":
            out.append(
                f"saturated: majority class "
                f"{deg.get('majority_label')!r} covers "
                f"{deg.get('majority_fraction')} of the rows")
        elif flag == "holdout_too_small":
            out.append(
                f"holdout_too_small: {probe.get('test_rows', 0)} held-out rows "
                f"(< {THRESHOLDS['min_shortcut_holdout_rows']})")
        elif flag == "too_small_to_score":
            out.append(
                f"too_small_to_score: {entry.get('rows_scorable')} scorable rows "
                f"(< {THRESHOLDS['min_scorable_rows']})")
        elif flag == "single_label":
            out.append(
                "single_label: every scorable row carries the label "
                f"{deg.get('majority_label')!r}")
        elif flag == "group_overlap":
            go = entry.get("group_overlap") or {}
            out.append(
                f"group_overlap: {go.get('test_rows_in_shared_group')} of "
                f"{go.get('test_rows')} held-out rows share a group with train")
        elif flag == "record_id_overlap":
            ro = entry.get("record_overlap") or {}
            out.append(
                f"record_id_overlap: {ro.get('record_id_overlap')} record ids "
                f"appear on both sides of the split")
        elif flag == "answer_literal_leak":
            al = entry.get("answer_leakage") or {}
            out.append(
                f"answer_literal_leak: the label appears in the evidence on "
                f"{al.get('answer_literal_in_evidence')} of "
                f"{al.get('rows_checked')} rows "
                f"(rate {al.get('evidence_leak_rate')})")
        elif flag == "near_duplicate_leak":
            nd = entry.get("near_duplicates") or {}
            out.append(
                f"near_duplicate_leak: {nd.get('test_rows_sim_ge_0.9')} of "
                f"{nd.get('test_rows_sampled')} sampled held-out rows are "
                f"near-duplicates of a train row")
        else:
            out.append(flag)
    return out


def classify(family_file: str, path: str | None, entry: dict | None,
             retired: bool) -> dict:
    """Turn one family's audit entry into a status.

    `entry` is the independent audit's own per-family measurement, or None
    when no rule covers the file (fail-closed).
    """
    base = {
        "family": family_file,
        "path": path,
        "retired": retired,
        "status": STATUS_UNKNOWN,
        "reason": "",
        "reasons": [],
        "validity_flags": [],
        "evaluable": False,
        "evaluable_reason": None,
        "rows_total": None,
        "rows_scorable": 0,
        "n_labels": 0,
        "label_distribution": {},
        "majority_label": None,
        "majority_fraction": None,
        "split_rows": {},
        "shortcut_floor": {"available": False},
        "audit_usable_as_evidence": None,
    }
    if entry is None:
        base["status"] = STATUS_UNKNOWN
        base["reason"] = (
            "no scoring or validity rule covers this family file; "
            "fail-closed: not primary")
        base["reasons"] = [base["reason"]]
        base["evaluable_reason"] = "no scoring rule: the family is not scored"
        return base
    if entry.get("verdict") == "skipped_no_scorable_key":
        base["status"] = STATUS_NOT_SCORABLE
        base["reason"] = entry.get("reason", "not exactly scorable")
        base["reasons"] = [base["reason"]]
        base["rows_total"] = entry.get("rows")
        base["evaluable_reason"] = base["reason"]
        return base

    flags = list(entry.get("validity_flags") or [])
    deg = entry.get("degeneracy") or {}
    per_split = (entry.get("split_drift") or {}).get(
        "per_split_label_distribution") or {}
    split_rows = {sp: sum(v.values()) for sp, v in per_split.items()}
    shortcut = _shortcut_floor(entry)
    n_labels = int(deg.get("n_labels") or 0)
    rows_scorable = int(entry.get("rows_scorable") or 0)

    base.update({
        "rows_total": entry.get("rows_total"),
        "rows_scorable": rows_scorable,
        "n_labels": n_labels,
        "label_distribution": dict(deg.get("label_distribution") or {}),
        "majority_label": deg.get("majority_label"),
        "majority_fraction": deg.get("majority_fraction"),
        "split_rows": dict(sorted(split_rows.items())),
        "shortcut_floor": shortcut,
        "validity_flags": flags,
        "audit_usable_as_evidence": entry.get("usable_as_evidence"),
    })

    # A shortcut accuracy is only believed on a holdout big enough to carry
    # it, and only when the label space has more than one class (with one
    # class every shortcut scores 1.000 by construction).
    dominated = False
    if (n_labels >= THRESHOLDS["min_labels"]
            and shortcut.get("available")
            and (shortcut.get("heldout_rows") or 0)
            >= THRESHOLDS["min_shortcut_holdout_rows"]):
        best = shortcut.get("best_train_only_accuracy")
        dominated = best is not None and best >= THRESHOLDS[
            "shortcut_dominance_accuracy"]
    if dominated:
        shortcut["shortcut_dominated"] = True
        shortcut["shortcut_dominance_reason"] = (
            f"a train-only baseline ({shortcut.get('best_train_only_baseline')}) "
            f"scores {shortcut.get('best_train_only_accuracy')} on the "
            f"{shortcut.get('heldout_rows')} held-out rows, at or above "
            f"{THRESHOLDS['shortcut_dominance_accuracy']}")

    hard = [f for f in flags if f in HARD_FLAGS]
    soft = [f for f in flags if f in SOFT_FLAGS]
    reasons = _flag_reasons(hard + soft, entry)
    if dominated:
        reasons.append(shortcut["shortcut_dominance_reason"])

    if n_labels < THRESHOLDS["min_labels"]:
        base["evaluable"] = False
        base["evaluable_reason"] = "single_label_not_evaluable"
    else:
        base["evaluable"] = True

    if hard or dominated:
        base["status"] = STATUS_INVALID
        base["reason"] = (
            "invalid as evaluation evidence: "
            + "; ".join(reasons))
    elif soft or rows_scorable < THRESHOLDS["min_primary_rows"]:
        if rows_scorable < THRESHOLDS["min_primary_rows"] and not soft:
            reasons.append(
                f"below the headline floor: {rows_scorable} scorable rows "
                f"(< {THRESHOLDS['min_primary_rows']})")
        base["status"] = STATUS_EXPLORATORY
        base["reason"] = "demoted: " + "; ".join(reasons)
    else:
        base["status"] = STATUS_PRIMARY
        base["reason"] = (
            f"no validity flag; {rows_scorable} scorable rows, {n_labels} "
            f"labels, train-only shortcut floor "
            f"{shortcut.get('best_train_only_accuracy')} on "
            f"{shortcut.get('heldout_rows')} held-out rows")
        if deg.get("verdict") == "near_degenerate":
            base["reason"] += (
                f" (majority class covers {deg.get('majority_fraction')} of the "
                f"rows; reported, not demoted: the minority class is still "
                f"worth detecting and the train-only floor shows whether it is)")
    base["reasons"] = reasons
    return base


def status_report(seed: int = 7,
                  extra_files: dict[str, str] | None = None) -> dict:
    """The full status report.

    `extra_files` maps a family file name to a repo-relative path. It exists
    so the tests can inject a family that no rule covers and prove the
    fail-closed path, without touching the dataset.
    """
    discovered = discover_family_files()
    discovered.update(extra_files or {})
    report = audit.run_audit(seed=seed)
    families: dict[str, dict] = {}
    for fname in sorted(discovered):
        rel = discovered[fname]
        entry = (report.get("families") or {}).get(fname)
        if entry is None and fname in audit.NOT_SCORABLE:
            entry = {"verdict": "skipped_no_scorable_key",
                     "reason": audit.NOT_SCORABLE[fname], "rows": 0}
        families[fname] = classify(fname, rel, entry,
                                    retired="retired_families" in rel)
    primary = sorted(f for f, s in families.items()
                     if s["status"] in PRIMARY_STATUSES)
    by_status = {st: sorted(f for f, s in families.items()
                            if s["status"] == st) for st in ALL_STATUSES}
    return {
        "status_version": "1",
        "seed": seed,
        "thresholds": dict(sorted(THRESHOLDS.items())),
        "rules": {
            "primary": (
                "no validity flag, at least "
                f"{THRESHOLDS['min_primary_rows']} scorable rows, at least "
                f"{THRESHOLDS['min_labels']} observed labels, and no "
                "train-only shortcut at or above "
                f"{THRESHOLDS['shortcut_dominance_accuracy']} on a holdout of "
                f"at least {THRESHOLDS['min_shortcut_holdout_rows']} rows"),
            "exploratory": (
                "shipped and scored, but demoted: too small, holdout too "
                "small, or a single observed label (accuracy is null with a "
                "reason)"),
            "invalid": (
                "a validity flag makes the family unusable as evaluation "
                "evidence: " + ", ".join(sorted(HARD_FLAGS))),
            "not_scorable": "no exactly-matchable scalar answer key",
            "unknown": (
                "a family file on disk that no rule covers: fail-closed, "
                "never primary"),
            "shortcut_baselines": list(TRAIN_ONLY_BASELINES),
            "shortcut_note": (
                "a baseline fitted on the held-out rows measures nothing, so "
                "only train-fitted baselines count as floors"),
        },
        "families": families,
        "primary_families": primary,
        "by_status": by_status,
    }


_CACHE: dict[int, dict] = {}


def cached_status_report(seed: int = 7) -> dict:
    """Status report for this process (the audit takes a few seconds)."""
    if seed not in _CACHE:
        _CACHE[seed] = status_report(seed=seed)
    return _CACHE[seed]


def status_of(family_file: str, seed: int = 7) -> dict:
    """Status of one family."""
    return cached_status_report(seed)["families"][family_file]


def primary_families(seed: int = 7) -> list[str]:
    """The families whose rows may enter the primary metric."""
    return list(cached_status_report(seed)["primary_families"])


def main() -> int:
    ap = argparse.ArgumentParser(
        description="print the audited status of every benchmark family")
    ap.add_argument("--json", action="store_true",
                    help="emit the machine-readable status report")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    rep = status_report(seed=args.seed)
    if args.json:
        print(json.dumps(rep, indent=2, sort_keys=True))
        return 0
    print(f"{'family':42} {'status':13} {'rows':>6} {'labs':>4} "
          f"{'floor':>7}  reason")
    for fam, s in sorted(rep["families"].items()):
        floor = s["shortcut_floor"].get("best_train_only_accuracy")
        print(f"{fam:42} {s['status']:13} {s['rows_scorable']:>6} "
              f"{s['n_labels']:>4} "
              f"{('%.4f' % floor) if floor is not None else 'n/a':>7}  "
              f"{s['reason'][:110]}")
    print()
    for st in ALL_STATUSES:
        fams = rep["by_status"][st]
        print(f"{st:13} {len(fams):>2}  {', '.join(fams) if fams else '-'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
