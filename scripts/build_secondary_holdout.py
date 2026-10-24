#!/usr/bin/env python3
"""Secondary, reproducible holdout for VLUN benchmark families A-V.

Why this exists: the committed splits were assigned by upstream repository
(Code4rena contest splits, then grouped into train/validation/test). The
independent audit showed that grouping does not always match the label
structure -- family R's held-out rows are a single contest that is 100%
one tier, so the train-majority predictor scores 0.000 on it. A split that
inherits the source's grouping cannot distinguish "learned the task" from
"learned the corpus composition".

This script builds an ADDITIVE evaluation layer. It never edits a
benchmark file, never changes a split in place and never rewrites an
answer key. Output lands in `benchmark/independent/` and carries the
full payload needed to re-derive every number.

Two holdouts per family:

  group_disjoint
      Groups (the unit that must not straddle the boundary: a record, a
      language, or a publishing source) are partitioned, and whole groups
      are held out. Nothing is shuffled row-wise.

  class_disjoint
      Every row of the two rarest labels is held out, and any group
      touching a held-out row is removed from the retained side, so the
      retained side contains zero examples of the held-out labels AND
      zero rows that share a group with one.

A family with fewer than two labels, or with a minority class below
`--min-minority`, cannot support an honest class-disjoint evaluation. That
is reported as `skipped_*` with the reason, never silently faked.

TASKS AND KEYS ARE SEPARATE FILES
----------------------------------
The model-facing task list carries the input payload and a task id that
reveals nothing. The answer key is a separate file. Nothing in the task
row exposes the answer: the record id and the group key are both withheld,
because for several families they ARE the answer (family K groups by the
record id's language prefix, families R/U/V group by the publishing source
whose tier is being asked).

THE KEY IS OPEN-KEY
-------------------
The key is committed in this repository, so anybody with the repository can
read it. This holdout is therefore OPEN-KEY: it measures whether a model
that has never been given the key can learn the task, and it does NOT
protect against a retrieval-augmented model that can search the repository.
It is not a hidden, protected or held-out-in-secret evaluation set, and
nothing in this layer may be described as one. The only genuinely private
evaluation in this repository is the VLUN-Prove private split, whose key
lives outside the tracked tree (scripts/build_prove_split.py).

Usage:
    python scripts/build_secondary_holdout.py            # build
    python scripts/build_secondary_holdout.py --check    # verify current
    python scripts/build_secondary_holdout.py --min-minority 10
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import importlib.util
import json
import pathlib
import random
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "benchmark" / "independent"
TASKS_NAME = "secondary_holdout_tasks.jsonl"
KEYS_NAME = "secondary_holdout_keys.jsonl"
MANIFEST_NAME = "secondary_holdout_manifest.json"

# Reuse the audit's family registry, projections and group function so the
# holdout and the audit cannot drift apart.
_spec = importlib.util.spec_from_file_location(
    "_audit", ROOT / "scripts" / "independent_benchmark_audit.py")
_audit = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_audit)

HOLDOUT_VERSION = "1"
HOLDOUT_FRACTION = 0.30

# Fields the model-facing task row must not carry. The check below enforces
# it, and the gate (scripts/check_eval_leakage.py) enforces it again.
ANSWER_FIELDS = ("gold", "label", "answer", "answer_key", "expected",
                 "original_id", "original_split", "group", "split")



def group_disjoint_split(fname: str, rows: list[dict], seed: int,
                         fraction: float = HOLDOUT_FRACTION) -> dict:
    """Hold out whole groups, keeping both sides as multi-class as we can.

    First checks whether a group-disjoint split is even meaningful. When
    every group carries exactly one label -- which is the case whenever
    the group key *is* the thing being predicted (family K groups by the
    language prefix of the record id; R and V group by the publishing
    source whose tier is being asked) -- holding out a group hands the
    model the answer for every row it removes. That split would look
    strict and measure nothing, so it is refused with evidence.
    """
    spec = _audit.FAMILIES[fname]
    groups = collections.defaultdict(list)
    for r in rows:
        groups[_audit.group_key(r, spec)].append(r)
    label_sets = {g: {_audit.gold_of(r, spec["projection"]) for r in rs}
                  for g, rs in groups.items()}
    if groups and all(len(rs) == 1 for rs in groups.values()):
        # Each group is one row, so the committed split is already as
        # record-disjoint as it can be; a group split adds no strictness.
        return {
            "kind": "group_disjoint",
            "verdict": "skipped_already_group_disjoint",
            "reason": (
                f"every one of the {len(groups)} {spec['group']} groups is a "
                f"single row, so the committed splits already hold out whole "
                f"records. Rebuilding the partition cannot make it stricter; "
                f"the residual risk in this family is split-composition "
                f"drift, not group overlap"),
            "groups_total": len(groups),
        }
    single_label_groups = sum(1 for s in label_sets.values() if len(s) == 1)
    if groups and single_label_groups == len(groups):
        return {
            "kind": "group_disjoint",
            "verdict": "skipped_group_determines_label",
            "reason": (
                f"every one of the {len(groups)} multi-row {spec['group']} "
                f"groups carries exactly one label, so the group key "
                f"determines the answer. Holding out a group would leak its "
                f"label to every row removed; a group-disjoint split here "
                f"measures the lookup, not the task"),
            "groups_total": len(groups),
            "groups_multi_row": single_label_groups,
            "group_label_map": {g: sorted(s)[0]
                                for g, s in sorted(label_sets.items())},
        }
    # Stratify groups by MAJORITY label, not by their full label set: keying
    # on the exact set would guarantee a single-class holdout whenever any
    # bucket happens to be pure.
    buckets = collections.defaultdict(list)
    for g, rs in groups.items():
        c = collections.Counter(_audit.gold_of(r, spec["projection"])
                                for r in rs)
        buckets[c.most_common(1)[0][0]].append(g)
    rng = random.Random(seed)
    held_groups: list[str] = []
    for label, gs in sorted(buckets.items()):
        gs = sorted(gs)
        if len(gs) == 1:
            # A single group cannot be fractionally held out. Taking it
            # would empty its bucket, which makes the split
            # uninformative rather than hard. Keep it.
            continue
        rng.shuffle(gs)
        want = min(max(1, round(len(gs) * fraction)), len(gs) - 1)
        held_groups.extend(gs[:want])
    held_set = set(held_groups)
    held = [r for g in held_groups for r in groups[g]]
    kept = [r for g, rs in groups.items() if g not in held_set for r in rs]
    verdict = ("built" if kept and held
               else "skipped_empty_retained_side"
               if not kept else "skipped_empty_holdout")
    return {
        "kind": "group_disjoint",
        "verdict": verdict,
        "groups_total": len(groups),
        "groups_held_out": len(held_set),
        "rows_held_out": len(held),
        "rows_retained": len(kept),
        "group_disjoint_verified": not (
            {_audit.group_key(r, spec) for r in held}
            & {_audit.group_key(r, spec) for r in kept}),
        "held_out_labels": dict(sorted(collections.Counter(
            _audit.gold_of(r, spec["projection"]) for r in held).items())),
        "retained_labels": dict(sorted(collections.Counter(
            _audit.gold_of(r, spec["projection"]) for r in kept).items())),
        "_held": held,
        "_kept": kept,
    }


def class_disjoint_split(fname: str, rows: list[dict],
                         min_minority: int) -> dict:
    """Hold out the two rarest labels entirely, group-disjoint."""
    spec = _audit.FAMILIES[fname]
    counts = collections.Counter(_audit.gold_of(r, spec["projection"])
                                 for r in rows)
    if len(counts) < 2:
        return {"kind": "class_disjoint", "verdict": "skipped_single_class",
                "reason": "the family has one label; class-disjoint evaluation "
                          "is vacuous because held-out labels cannot be unseen",
                "label_counts": dict(sorted(counts.items()))}
    rare = sorted(counts.items(), key=lambda x: (x[1], x[0]))[0]
    if rare[1] < min_minority:
        return {"kind": "class_disjoint",
                "verdict": "skipped_insufficient_minority_support",
                "reason": f"rarest label {rare[0]!r} has n={rare[1]}, below "
                          f"the --min-minority floor of {min_minority}; "
                          f"a holdout of {rare[1]} rows cannot support a "
                          f"stable class-disjoint estimate",
                "label_counts": dict(sorted(counts.items()))}
    hold_labels = {lab for lab, _ in
                   sorted(counts.items(), key=lambda x: (x[1], x[0]))[:2]}
    held = [r for r in rows
            if _audit.gold_of(r, spec["projection"]) in hold_labels]
    if not held:
        return {"kind": "class_disjoint", "verdict": "skipped_no_holdout_rows",
                "reason": "no rows matched the selected labels"}
    held_groups = {_audit.group_key(r, spec) for r in held}
    kept = [r for r in rows
            if _audit.group_key(r, spec) not in held_groups
            and _audit.gold_of(r, spec["projection"]) not in hold_labels]
    kept_labels = {_audit.gold_of(r, spec["projection"]) for r in kept}
    if not kept:
        # Two-label families hold out every label, which leaves nothing to
        # fit on. That is not a harder split, it is an empty one.
        return {"kind": "class_disjoint", "verdict": "skipped_empty_retained_side",
                "reason": (
                    f"holding out the two rarest labels removed every row "
                    f"({len(rows)} of {len(rows)}); the retained side is "
                    f"empty, so nothing can be fitted. A binary family "
                    f"cannot be evaluated class-disjoint"),
                "held_out_labels": sorted(hold_labels),
                "rows_held_out": len(held),
                "rows_retained": 0,
                "label_counts": dict(sorted(counts.items())),
                "_held": held, "_kept": kept}
    return {
        "kind": "class_disjoint",
        "verdict": "built",
        "held_out_labels": sorted(hold_labels),
        "rows_held_out": len(held),
        "rows_retained": len(kept),
        "group_disjoint_verified": not (
            held_groups & {_audit.group_key(r, spec) for r in kept}),
        "retained_contains_held_out_label": sorted(kept_labels & hold_labels),
        "held_out_labels_absent_from_retained": not (kept_labels & hold_labels),
        "label_counts": dict(sorted(counts.items())),
        "_held": held,
        "_kept": kept,
    }


def evaluate_shortcuts_on(fname: str, kept: list[dict], held: list[dict],
                          seed: int) -> dict:
    """Re-fit the meaningless baselines on `kept`, score them on `held`.

    This is the comparison that matters: if a shortcut does nearly as well
    on a group- and class-disjoint holdout as on the official test split,
    then the official split was measuring corpus composition, not skill.
    """
    spec = _audit.FAMILIES[fname]
    if not kept or not held:
        return {"verdict": "skipped_empty_side"}
    kg = [_audit.gold_of(r, spec["projection"]) for r in kept]
    hg = [_audit.gold_of(r, spec["projection"]) for r in held]
    space = sorted(set(kg))
    rng = random.Random(seed)
    out: dict = {"kept_rows": len(kept), "held_out_rows": len(held),
                 "kept_label_space": len(space)}

    def report(name, preds):
        acc = sum(1 for g, p in zip(hg, preds) if g == p) / len(hg)
        out[name] = {"accuracy": round(acc, 4),
                     "macro_f1": _audit.macro_f1(hg, preds),
                     "coverage": round(len(preds) / len(hg), 4)}

    maj = collections.Counter(kg).most_common(1)[0][0]
    report("majority_from_retained", [maj] * len(hg))
    # A shortcut that guesses the majority HELD-OUT label, which is only
    # possible if the evaluator peeked. Reported to expose how much of the
    # official score that peeking would buy.
    hmaj = collections.Counter(hg).most_common(1)[0][0]
    report("majority_heldout_oracle_peek", [hmaj] * len(hg))
    report("random_from_retained_space", [rng.choice(space) for _ in hg])
    w = [kg.count(g) / len(kg) for g in space]
    report("frequency_from_retained",
           [rng.choices(space, weights=w, k=1)[0] for _ in hg])
    kt = [set(_audit.WORD.findall(_audit.input_text(r).lower()))
          for r in kept]
    preds = []
    for r in held:
        q = set(_audit.WORD.findall(_audit.input_text(r).lower()))
        best, bj = -1.0, None
        for j, t in enumerate(kt):
            if not t or not q:
                continue
            inter = len(q & t)
            jac = inter / (len(q) + len(t) - inter)
            if jac > best:
                best, bj = jac, j
        preds.append(_audit.gold_of(kept[bj], spec["projection"])
                     if bj is not None else maj)
    report("input_retrieval", preds)
    gmap = collections.defaultdict(collections.Counter)
    for r in kept:
        gmap[_audit.group_key(r, spec)][_audit.gold_of(r, spec["projection"])] += 1
    preds, cov = [], 0
    for r in held:
        g = _audit.group_key(r, spec)
        if g in gmap:
            cov += 1
            preds.append(gmap[g].most_common(1)[0][0])
        else:
            preds.append(maj)
    acc = sum(1 for g, p in zip(hg, preds) if g == p) / len(hg)
    out["group_lookup"] = {"accuracy": round(acc, 4),
                           "macro_f1": _audit.macro_f1(hg, preds),
                           "coverage": round(cov / len(hg), 4)}
    scored = [v["accuracy"] for v in out.values()
              if isinstance(v, dict) and "accuracy" in v]
    out["best_shortcut_accuracy"] = round(max(scored), 4) if scored else None
    out["worst_honest_shortcut_accuracy"] = round(
        min(out["majority_from_retained"]["accuracy"],
            out["random_from_retained_space"]["accuracy"],
            out["input_retrieval"]["accuracy"]), 4)
    return out


def task_pseudonym(fname: str, holdout: str, original_id: str) -> str:
    """A task id that carries no information about the answer.

    The original task id is withheld because it names the record, and for
    several families the record id (or the group the record belongs to) IS
    the answer. The pseudonym is a stable digest of the same three facts, so
    a grader can join the task file to the key file, and a reader of the
    task file learns nothing beyond the fact that the row exists.
    """
    digest = hashlib.sha256(
        f"{fname}|{holdout}|{original_id}".encode("utf-8")).hexdigest()
    return f"holdout-{digest[:16]}"


def _build(seed: int, min_minority: int) -> tuple[dict, list[dict], list[dict]]:
    tasks: list[dict] = []
    keys: list[dict] = []
    payload_leaks: dict[str, int] = {}
    payload_leak_rows = 0
    manifest: dict = {
        "holdout_version": HOLDOUT_VERSION,
        "generated_by": "scripts/build_secondary_holdout.py",
        "seed": seed,
        "holdout_fraction": HOLDOUT_FRACTION,
        "min_minority": min_minority,
        "method": (
            "group_disjoint: whole groups partitioned with a seeded shuffle, "
            "stratified by each group's label set. class_disjoint: all rows of "
            "the two rarest labels held out, then every group touching a "
            "held-out row removed from the retained side, so retained labels "
            "and retained groups are both disjoint from the holdout."),
        "independence_guarantee": (
            "Built only from the committed benchmark files. No model, "
            "prompt or threshold was tuned against it, and it did not exist "
            "while any published score was produced."),
        "additive": (
            "This layer is separate from benchmark/. No source benchmark "
            "file, split, answer key or score is modified by this script."),
        "model_facing_tasks": {
            "file": f"benchmark/independent/{TASKS_NAME}",
            "carries": ["holdout_task_id", "family_file", "holdout", "input"],
            "does_not_carry": list(ANSWER_FIELDS),
            "task_id": ("a digest of (family, holdout, original id): stable, "
                        "joinable to the key file, and it names nothing the "
                        "answer depends on"),
        },
        "answer_key": {
            "file": f"benchmark/independent/{KEYS_NAME}",
            "key_status": "OPEN_KEY",
            "committed_in_repository": True,
            "retrievable_by": ("anyone with this repository: the key file is "
                               "a tracked file"),
            "implication": (
                "this holdout is OPEN-KEY. It measures whether a model that "
                "has not been handed the key can learn the task. It does NOT "
                "protect against a retrieval-augmented model that can search "
                "the repository, and it must never be described as hidden, "
                "protected against repository-level leakage, or not "
                "accessible. The only genuinely private evaluation in this "
                "repository is the VLUN-Prove private split, whose key lives "
                "outside the tracked tree."),
        },
        "families": {},
    }
    for fname in sorted(_audit.FAMILIES):
        spec = _audit.FAMILIES[fname]
        if fname in _audit.NOT_SCORABLE:
            manifest["families"][fname] = {
                "verdict": "skipped_no_scorable_key",
                "reason": _audit.NOT_SCORABLE[fname],
            }
            continue
        rows = _audit.scorable_rows(fname, _audit.load_family(fname))
        if not rows:
            manifest["families"][fname] = {"verdict": "skipped_no_labeled_rows"}
            continue
        gd = group_disjoint_split(fname, rows, seed)
        cd = class_disjoint_split(fname, rows, min_minority)
        gd_built = gd.get("verdict") == "built"
        entry = {
            "rows_available": len(rows),
            "group_disjoint": {k: v for k, v in gd.items()
                               if not k.startswith("_")},
            "class_disjoint": {k: v for k, v in cd.items()
                               if not k.startswith("_")},
            "shortcuts_group_disjoint": (
                evaluate_shortcuts_on(fname, gd["_kept"], gd["_held"], seed)
                if gd_built
                else {"verdict": gd["verdict"], "reason": gd["reason"]}),
            "shortcuts_class_disjoint": (
                evaluate_shortcuts_on(fname, cd["_kept"], cd["_held"], seed)
                if cd.get("verdict") == "built"
                else {"verdict": cd.get("verdict"), "reason": cd.get("reason")}),
        }
# A holdout that is one class cannot discriminate between models,
        # so it must never be quoted as a headline result.
        hl = entry["group_disjoint"].get("held_out_labels") or {}
        entry["group_disjoint"]["single_class_holdout"] = len(hl) == 1
        entry["group_disjoint"]["usable_for_comparison"] = (
            len(hl) > 1
            and entry["group_disjoint"].get("verdict") == "built")
        manifest["families"][fname] = entry
        for holdout, held in (("group_disjoint", gd.get("_held", [])),
                              ("class_disjoint", cd.get("_held", []))):
            if holdout == "class_disjoint" and cd.get("verdict") != "built":
                continue
            for r in held:
                original_id = _audit.task_id(r, spec["id"])
                tid = task_pseudonym(fname, holdout, original_id)
                tasks.append({
                    "holdout_task_id": tid,
                    "family_file": fname,
                    "holdout": holdout,
                    "input": r.get("input"),
                })
                keys.append({
                    "holdout_task_id": tid,
                    "family_file": fname,
                    "holdout": holdout,
                    "original_id": original_id,
                    "original_split": str(r.get("split")),
                    "group": _audit.group_key(r, spec),
                    "gold": _audit.gold_of(r, spec["projection"]),
                    "key_status": "OPEN_KEY",
                })
                gold = _audit.gold_of(r, spec["projection"])
                if (gold and gold not in ("true", "false") and len(gold) >= 3
                        and re.search(r"(?<![a-z0-9])" + re.escape(gold)
                                      + r"(?![a-z0-9])",
                                      _audit.evidence_text(r).lower())):
                    payload_leaks[fname] = payload_leaks.get(fname, 0) + 1
                    payload_leak_rows += 1
    manifest["tasks_written"] = len(tasks)
    manifest["keys_written"] = len(keys)
    manifest["payload_answer_literal_overlap"] = {
        "rows": payload_leak_rows,
        "by_family": dict(sorted(payload_leaks.items())),
        "note": ("the model-facing payload is copied verbatim from the "
                 "benchmark, so a family whose own evidence names the answer "
                 "leaks it here too. That is a benchmark defect, measured "
                 "by scripts/independent_benchmark_audit.py (K and L are the "
                 "high-severity cases), and it is reported here rather than "
                 "hidden: this holdout is open-key and is not claimed to be "
                 "leakage-proof"),
    }
    return manifest, tasks, keys


def build(seed: int, min_minority: int) -> tuple[dict, list[dict]]:
    """The manifest and the model-facing task rows (no answer material)."""
    manifest, tasks, _keys = _build(seed, min_minority)
    return manifest, tasks


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--min-minority", type=int, default=5)
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    manifest, tasks, keys = _build(args.seed, args.min_minority)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    mpath = OUT_DIR / MANIFEST_NAME
    tpath = OUT_DIR / TASKS_NAME
    kpath = OUT_DIR / KEYS_NAME
    mtext = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    ttext = "".join(json.dumps(t, sort_keys=True, ensure_ascii=False) + "\n"
                    for t in tasks)
    ktext = "".join(json.dumps(k, sort_keys=True, ensure_ascii=False) + "\n"
                    for k in keys)
    leaked = sorted({f for t in tasks for f in ANSWER_FIELDS if f in t})
    if leaked:
        print("model-facing task rows carry answer material: "
              + ", ".join(leaked), file=sys.stderr)
        return 1
    if args.check:
        bad = []
        for p, want in ((mpath, mtext), (tpath, ttext), (kpath, ktext)):
            if not p.is_file():
                bad.append(f"missing {p}")
            elif p.read_text(encoding="utf-8") != want:
                bad.append(f"STALE {p}")
        if bad:
            print("; ".join(bad) + " -- run: python "
                  "scripts/build_secondary_holdout.py", file=sys.stderr)
            return 1
        print("secondary holdout is current")
        return 0
    mpath.write_text(mtext, encoding="utf-8", newline="\n")
    tpath.write_text(ttext, encoding="utf-8", newline="\n")
    kpath.write_text(ktext, encoding="utf-8", newline="\n")
    built = sum(1 for v in manifest["families"].values()
                if v.get("class_disjoint", {}).get("verdict") == "built")
    skipped = sum(1 for v in manifest["families"].values()
                  if v.get("class_disjoint", {}).get("verdict", "").startswith(
                      "skipped"))
    print(f"wrote {mpath}")
    print(f"wrote {tpath} ({len(tasks)} model-facing tasks, no answer fields)")
    print(f"wrote {kpath} ({len(keys)} OPEN-KEY rows, committed in-repo)")
    print(f"class-disjoint built for {built} families; skipped for {skipped}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())