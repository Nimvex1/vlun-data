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

CLEAN AND EXPLORATORY PARTITIONS
--------------------------------
A holdout row is only model-facing-safe if its copied payload does not
contain its own gold scalar as a literal token. `evidence_text()` (the
same definition the independent audit uses) removes instruction scaffolding
and label vocabularies, then a word-boundary match is run against the gold.

  clean
      `secondary_holdout_tasks.jsonl` -- zero known literal-answer overlap,
      recomputed from the written payload and the committed benchmark files
      by `--check`. This is the only partition claimed leakage-free.

  exploratory
      `secondary_holdout_exploratory_tasks.jsonl` -- rows that still carry
      their answer in the payload because the SOURCE family's evidence names
      it. They are kept, separately and explicitly labelled, so the failure
      is visible rather than silently dropped. They are NOT independent,
      leakage-free or usable as headline evidence.

Three response modes are used, per family and per row:

  * clean rows are copied unchanged;
  * rows whose answer literal occurs only in non-essential provenance text
    (family O: the word appears in a source title / URL slug, not in the
    scope evidence) are transformed: the literal span is replaced by
    `[redacted]` and a provenance record (field, rule, before/after SHA-256)
    is written to the manifest;
  * rows whose answer literal is the evidence the task asks the model to
    reconcile (family L: the published severity IS the answer) or whose
    evidence IS the language name (family K: repositories, file extensions
    and titles) are excluded from the clean partition. Transforming them
    would destroy the task, so they are reported as exploratory instead.

TASKS AND KEYS ARE SEPARATE FILES
----------------------------------
The model-facing task list carries the input payload and a task id that
reveals nothing. The answer keys are separate files, one per partition.
Nothing in a task row exposes the answer: the record id and the group key
are both withheld, because for several families they ARE the answer
(family K groups by the record id's language prefix, families R/U/V group
by the publishing source whose tier is being asked).

THE KEY IS NOT COMMITTED IN THIS REPOSITORY
--------------------------------------------
`secondary_holdout_keys.jsonl` is generated in the local working tree and
is NOT tracked by git (`git ls-files` does not list it). It is withheld
from the repository, but it is NOT secret: the split is deterministic
(seed in the manifest) and the key is regenerable from the committed
benchmark files by running this script. `OPEN_KEY` therefore means "no
confidentiality", not "published here". `--check` verifies the manifest and
both task files without reading the key; if the key file is absent (as in a
fresh checkout or CI) that part is reported as local-only rather than
failed. Nothing in this layer may be described as a private or protected
evaluation; the only genuinely private evaluation in this repository is the
VLUN-Prove private split, whose key lives outside the tracked tree.

Usage:
    python scripts/build_secondary_holdout.py            # build
    python scripts/build_secondary_holdout.py --check    # verify current
    python scripts/build_secondary_holdout.py --min-minority 10
"""
from __future__ import annotations

import argparse
import collections
import copy
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
EXPLORATORY_TASKS_NAME = "secondary_holdout_exploratory_tasks.jsonl"
EXPLORATORY_KEYS_NAME = "secondary_holdout_exploratory_keys.jsonl"
MANIFEST_NAME = "secondary_holdout_manifest.json"

# Reuse the audit's family registry, projections and group function so the
# holdout and the audit cannot drift apart.
_spec = importlib.util.spec_from_file_location(
    "_audit", ROOT / "scripts" / "independent_benchmark_audit.py")
_audit = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_audit)

HOLDOUT_VERSION = "2"
HOLDOUT_FRACTION = 0.30

# Fields the model-facing task row must not carry. The check below enforces
# it, and the gate (scripts/check_eval_leakage.py) enforces it again.
ANSWER_FIELDS = ("gold", "label", "answer", "answer_key", "expected",
                 "original_id", "original_split", "group", "split")
TASK_FIELDS = ("holdout_task_id", "family_file", "holdout", "input")
PARTITIONS = ("group_disjoint", "class_disjoint")
CLEAN_STATUSES = ("clean", "transformed")

REDACTION_RULE = "word_boundary_answer_literal_redaction_v1"
REDACTION_PLACEHOLDER = "[redacted]"

# Families whose held-out rows cannot be made literal-clean without deleting
# the artefact the task asks the model to read. They are excluded from the
# clean partition as a family and kept only as labelled exploratory rows.
EXCLUDED_FAMILIES = {
    "K_language_ecosystem_routing.jsonl": (
        "the gold is the language name and the model-facing evidence IS that "
        "name: repository slugs (OpenZeppelin/cairo-contracts), file "
        "extensions (*.cairo, *.move), component names and prose "
        "('Cairo VM', 'Move bytecode verifier'). Redacting every literal "
        "occurrence truncates the routing evidence itself, and the remaining "
        "ecosystem names (Sui/Aptos/Starknet) still determine the language. "
        "20 of the 23 held-out rows leak; the family is therefore reported "
        "as exploratory, not repaired by cosmetic redaction"),
}

# Families where the answer word appears ONLY in source provenance (a title
# or URL slug), never in the evidence the task is about. Redacting those
# fields leaves the components, prose and remaining sources intact.
TRANSFORM_FAMILIES = {
    "O_record_class_and_scope.jsonl": (
        "the record-class word occurs only in a source title or URL slug "
        "('... DoS vulnerability needs to be applied', '... Incident Report "
        "...'); the scope evidence (components, prose, other sources) is "
        "untouched, so the literal can be redacted without weakening the "
        "task"),
}


# ---------------------------------------------------------------------------
# Group/class-disjoint split construction
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Payload leakage: detection, redaction and provenance
# ---------------------------------------------------------------------------

def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def answer_pattern(gold: str) -> re.Pattern | None:
    """The audit's own word-boundary answer matcher, or None if too short."""
    if not gold or gold in ("true", "false") or len(gold) < 3:
        return None
    return re.compile(r"(?<![a-z0-9])" + re.escape(gold) + r"(?![a-z0-9])",
                      re.IGNORECASE)


def _evidence_leaves(value, path=(), top=False):
    """Yield (path_tuple, string) for every string `evidence_text` reads.

    Mirrors `audit.evidence_text`: instruction scaffolding at the top level
    and prompt/question keys at any depth are excluded. Those name the whole
    label space and are not evidence.
    """
    if isinstance(value, dict):
        for k, v in value.items():
            if top and k in _audit.INSTRUCTION_KEYS:
                continue
            if k in _audit.DROP_KEYS:
                continue
            yield from _evidence_leaves(v, path + (k,), False)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from _evidence_leaves(v, path + (i,), False)
    elif isinstance(value, str):
        yield path, value


def _render_path(parts) -> str:
    out = ""
    for p in parts:
        if isinstance(p, int):
            out += f"[{p}]"
        else:
            out += ("." if out else "") + p
    return "input." + out if out else "input"


def _parse_path(path: str) -> list:
    if path.startswith("input."):
        path = path[len("input."):]
    parts: list = []
    for seg in path.split("."):
        m = re.match(r"^([^\[]*)((?:\[\d+\])*)$", seg)
        name, idxs = m.group(1), m.group(2)
        if name:
            parts.append(name)
        parts.extend(int(x) for x in re.findall(r"\[(\d+)\]", idxs))
    return parts


def _leaf_at(node, path: str):
    for part in _parse_path(path):
        node = node[part]
    return node


def find_answer_leaks(input_obj, gold: str) -> list[tuple[str, str]]:
    """(field path, field text) where the gold literal occurs in evidence."""
    pat = answer_pattern(gold)
    if pat is None:
        return []
    return [(_render_path(path), text)
            for path, text in _evidence_leaves(input_obj, (), True)
            if pat.search(text)]


def redact_answer_literals(input_obj, gold: str,
                           leaking: list[tuple[str, str]]):
    """Replace the gold literal in the leaking evidence fields only.

    Returns the transformed input and one provenance record per touched
    field. The record stores the field path, the rule, and before/after
    SHA-256 hashes -- never the answer text itself.
    """
    pat = answer_pattern(gold)
    targets = {field for field, _ in leaking}
    records: list[dict] = []

    def walk(value, path):
        if isinstance(value, dict):
            return {k: walk(v, path + (k,)) for k, v in value.items()}
        if isinstance(value, list):
            return [walk(v, path + (i,)) for i, v in enumerate(value)]
        if isinstance(value, str):
            field = _render_path(path)
            if field in targets:
                replaced, count = pat.subn(REDACTION_PLACEHOLDER, value)
                if count:
                    records.append({
                        "field": field,
                        "rule": REDACTION_RULE,
                        "before_sha256": _sha256(value),
                        "after_sha256": _sha256(replaced),
                        "occurrences": count,
                        "replacement": REDACTION_PLACEHOLDER,
                    })
                    return replaced
        return value

    transformed = walk(input_obj, ())
    records.sort(key=lambda r: r["field"])
    return transformed, records


def classify_held_row(fname: str, holdout: str, row: dict) -> dict:
    """Decide clean / transformed / contaminated for one held-out row."""
    spec = _audit.FAMILIES[fname]
    gold = _audit.gold_of(row, spec["projection"])
    original = copy.deepcopy(row.get("input"))
    leaks = find_answer_leaks(original, gold)
    payload = original
    transforms: list[dict] = []
    status = "clean"
    reason = ""
    if fname in EXCLUDED_FAMILIES:
        if leaks:
            status = "contaminated"
            reason = "excluded_family_answer_leaking"
        else:
            status = "family_excluded_clean"
            reason = "clean_row_but_family_excluded"
    elif leaks:
        if fname in TRANSFORM_FAMILIES:
            payload, transforms = redact_answer_literals(original, gold, leaks)
            if find_answer_leaks(payload, gold):
                # The redaction did not close every occurrence: keep the
                # untouched payload and report it as exploratory.
                payload = original
                transforms = []
                status = "contaminated"
                reason = "redaction_incomplete"
            else:
                status = "transformed"
                reason = "answer_literal_redacted_in_provenance_text"
        else:
            status = "contaminated"
            reason = "answer_literal_in_payload"
    return {
        "row": row,
        "gold": gold,
        "payload": payload,
        "leaks_before": leaks,
        "status": status,
        "reason": reason,
        "transforms": transforms,
        "holdout": holdout,
        "original_id": _audit.task_id(row, spec["id"]),
    }


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

def _apply_clean_stats(split: dict, classified: list[dict],
                       clean: list[dict]) -> dict:
    """Attach clean-partition counts to a split definition, in place."""
    labels = dict(sorted(collections.Counter(
        c["gold"] for c in clean).items()))
    stats = {
        "rows_held_out_before_filter": len(classified),
        "held_out_labels_before_filter": split.get("held_out_labels", {}),
        "rows_held_out": len(clean),
        "held_out_labels": labels,
        "rows_transformed_and_clean": sum(
            1 for c in classified if c["status"] == "transformed"),
        "rows_excluded_contaminated": sum(
            1 for c in classified if c["status"] == "contaminated"),
        "rows_excluded_with_family_clean": sum(
            1 for c in classified if c["status"] == "family_excluded_clean"),
        "literal_answer_overlap_in_clean": sum(
            1 for c in clean if find_answer_leaks(c["payload"], c["gold"])),
    }
    split.update(stats)
    if not clean:
        split["verdict"] = "skipped_all_held_rows_answer_leaking"
        split["reason"] = (
            "every held-out row either carries its own answer literal in the "
            "model-facing payload or belongs to a family excluded for that "
            "reason; no row of this split can enter the clean partition")
    elif len(clean) < 30:
        split["clean_holdout_too_small"] = True
    return stats


def _build(seed: int, min_minority: int) -> tuple[dict, list, list, list, list]:
    tasks: list[dict] = []
    keys: list[dict] = []
    exploratory_tasks: list[dict] = []
    exploratory_keys: list[dict] = []
    transforms: list[dict] = []
    contaminated_ids: list[str] = []
    exploratory_ids: list[str] = []
    overlap_before: collections.Counter = collections.Counter()
    by_family_counts: dict[str, dict] = {}
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
            "and retained groups are both disjoint from the holdout. Held-out "
            "rows whose payload contains the gold scalar are then either "
            "redacted (only where the literal sits in non-essential "
            "provenance text) or excluded from the clean partition."),
        "independence_guarantee": (
            "The clean partition is built only from the committed benchmark "
            "files. No model, prompt or threshold was tuned against it, and "
            "it did not exist while any published score was produced. This "
            "guarantee applies to rows in secondary_holdout_tasks.jsonl only; "
            "the exploratory file is not independent evidence."),
        "additive": (
            "This layer is separate from benchmark/. No source benchmark "
            "file, split, answer key or score is modified by this script."),
        "model_facing_tasks": {
            "file": f"benchmark/independent/{TASKS_NAME}",
            "carries": list(TASK_FIELDS),
            "does_not_carry": list(ANSWER_FIELDS),
            "task_id": ("a digest of (family, holdout, original id): stable, "
                        "joinable to the key file, and it names nothing the "
                        "answer depends on"),
            "exploratory_file": (
                f"benchmark/independent/{EXPLORATORY_TASKS_NAME}"),
            "exploratory_note": (
                "rows in the exploratory file still carry their answer in the "
                "payload because the source family's evidence names it. They "
                "are labelled exploratory and must never be counted as clean, "
                "independent or leakage-free holdout results"),
        },
        "answer_key": {
            "file": f"benchmark/independent/{KEYS_NAME}",
            "exploratory_file": (
                f"benchmark/independent/{EXPLORATORY_KEYS_NAME}"),
            "key_status": "OPEN_KEY",
            "key_status_meaning": (
                "OPEN_KEY means the key provides no confidentiality: the split "
                "is deterministic and the key is regenerable from the "
                "committed benchmark files at the recorded seed. It does NOT "
                "mean the key file is tracked or published in this "
                "repository"),
            "committed_in_repository": False,
            "tracked_in_git": False,
            "visibility": "local_only_untracked",
            "withheld_from_repository": True,
            "retrievable_by": (
                "anyone who can run scripts/build_secondary_holdout.py against "
                "the committed benchmark files; the key file itself is not "
                "part of the repository"),
            "ci_verification": (
                "--check verifies the manifest and both task files without "
                "reading the key. If the key file is absent (fresh checkout or "
                "CI) its contents are reported as local-only and unverified, "
                "not treated as missing evidence"),
            "implication": (
                "the key file exists only in a local working tree and is not "
                "tracked by git. It is withheld from the repository but it is "
                "not secret, because the same key is reproducible from public "
                "committed sources. This layer must never be described as a "
                "private or protected evaluation; the only genuinely private "
                "evaluation in this repository is the VLUN-Prove private "
                "split, whose key lives outside the tracked tree."),
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
        clean_rows: dict[str, list[dict]] = {}
        fam_counts = {
            "rows_held_out": 0,
            "rows_with_overlap_before": 0,
            "rows_transformed_and_clean": 0,
            "rows_excluded_contaminated": 0,
            "rows_excluded_with_family_clean": 0,
            "rows_in_clean_holdout": 0,
            "literal_answer_overlap_in_clean": 0,
        }
        for holdout, split in (("group_disjoint", gd),
                               ("class_disjoint", cd)):
            if split.get("verdict") != "built":
                continue
            held = split["_held"]
            classified = [classify_held_row(fname, holdout, r) for r in held]
            clean = [c for c in classified if c["status"] in CLEAN_STATUSES]
            clean_rows[holdout] = [dict(c["row"], input=c["payload"])
                                   for c in clean]
            stats = _apply_clean_stats(split, classified, clean)
            fam_counts["rows_held_out"] += stats["rows_held_out_before_filter"]
            fam_counts["rows_with_overlap_before"] += len(
                [c for c in classified if c["leaks_before"]])
            fam_counts["rows_transformed_and_clean"] += stats[
                "rows_transformed_and_clean"]
            fam_counts["rows_excluded_contaminated"] += stats[
                "rows_excluded_contaminated"]
            fam_counts["rows_excluded_with_family_clean"] += stats[
                "rows_excluded_with_family_clean"]
            fam_counts["rows_in_clean_holdout"] += stats["rows_held_out"]
            fam_counts["literal_answer_overlap_in_clean"] += stats[
                "literal_answer_overlap_in_clean"]
            for c in classified:
                tid = task_pseudonym(fname, holdout, c["original_id"])
                task = {
                    "holdout_task_id": tid,
                    "family_file": fname,
                    "holdout": holdout,
                    "input": c["payload"],
                }
                key = {
                    "holdout_task_id": tid,
                    "family_file": fname,
                    "holdout": holdout,
                    "original_id": c["original_id"],
                    "original_split": str(c["row"].get("split")),
                    "group": _audit.group_key(c["row"], spec),
                    "gold": c["gold"],
                    "key_status": "OPEN_KEY",
                    "partition": ("clean" if c["status"] in CLEAN_STATUSES
                                  else "exploratory"),
                }
                if c["status"] in CLEAN_STATUSES:
                    tasks.append(task)
                    keys.append(key)
                else:
                    exploratory_tasks.append(task)
                    exploratory_keys.append(key)
                    exploratory_ids.append(tid)
                    if find_answer_leaks(task["input"], c["gold"]):
                        contaminated_ids.append(tid)
                for tr in c["transforms"]:
                    transforms.append({
                        "holdout_task_id": tid,
                        "family_file": fname,
                        "holdout": holdout,
                        **tr,
                    })
        for holdout, split in (("group_disjoint", gd),
                               ("class_disjoint", cd)):
            if split.get("verdict") == "built":
                clean_held = clean_rows.get(holdout, [])
                split["single_class_holdout"] = (
                    len(split.get("held_out_labels", {})) == 1)
                split["usable_for_comparison"] = (
                    len(split.get("held_out_labels", {})) > 1
                    and len(clean_held) >= 30)
            elif split.get("kind") == "group_disjoint":
                split.setdefault("single_class_holdout", False)
                split.setdefault("usable_for_comparison", False)
        entry = {
            "rows_available": len(rows),
            "group_disjoint": {k: v for k, v in gd.items()
                               if not k.startswith("_")},
            "class_disjoint": {k: v for k, v in cd.items()
                               if not k.startswith("_")},
            "shortcuts_group_disjoint": (
                evaluate_shortcuts_on(fname, gd["_kept"],
                                      clean_rows.get("group_disjoint", []),
                                      seed)
                if gd.get("verdict") == "built"
                and clean_rows.get("group_disjoint")
                else {"verdict": gd.get("verdict"),
                      "reason": gd.get("reason")}),
            "shortcuts_class_disjoint": (
                evaluate_shortcuts_on(fname, cd["_kept"],
                                      clean_rows.get("class_disjoint", []),
                                      seed)
                if cd.get("verdict") == "built"
                and clean_rows.get("class_disjoint")
                else {"verdict": cd.get("verdict"),
                      "reason": cd.get("reason")}),
        }
        if (fam_counts["rows_excluded_contaminated"]
                and not fam_counts["rows_in_clean_holdout"]):
            status = "excluded_family_contaminated"
        elif fam_counts["rows_excluded_contaminated"]:
            status = "partially_contaminated"
        elif fam_counts["rows_transformed_and_clean"]:
            status = "clean_after_redaction"
        elif fam_counts["rows_in_clean_holdout"]:
            status = "clean"
        else:
            status = "no_holdout_rows"
        entry["clean_holdout_status"] = status
        entry["payload_leakage"] = {
            **fam_counts,
            "clean_holdout_status": status,
            "reason": EXCLUDED_FAMILIES.get(fname, ""),
        }
        manifest["families"][fname] = entry
        overlap_before[fname] = fam_counts["rows_with_overlap_before"]
        by_family_counts[fname] = fam_counts

    contaminated_ids = sorted(contaminated_ids)
    exploratory_ids = sorted(exploratory_ids)
    clean_by_family = {f: c["rows_in_clean_holdout"]
                       for f, c in by_family_counts.items()
                       if c["rows_in_clean_holdout"]}
    transformed_by_family = {
        f: c["rows_transformed_and_clean"] for f, c in by_family_counts.items()
        if c["rows_transformed_and_clean"]}
    contaminated_by_family = {
        f: c["rows_excluded_contaminated"] for f, c in by_family_counts.items()
        if c["rows_excluded_contaminated"]}
    family_excluded_by_family = {
        f: c["rows_excluded_with_family_clean"]
        for f, c in by_family_counts.items()
        if c["rows_excluded_with_family_clean"]}
    clean_leaks = sum(c["literal_answer_overlap_in_clean"]
                      for c in by_family_counts.values())
    manifest["clean_holdout"] = {
        "tasks_file": f"benchmark/independent/{TASKS_NAME}",
        "rows": len(tasks),
        "by_family": dict(sorted(clean_by_family.items())),
        "literal_answer_overlap": clean_leaks,
        "verification": (
            "recomputed from the written payload and the committed benchmark "
            "families by scripts/build_secondary_holdout.py --check, without "
            "reading the answer key; a row is leaking when evidence_text() "
            "contains the gold scalar as a word-boundary literal"),
        "claim": (
            "every row in this file has ZERO known literal-answer overlap. "
            "This is the only partition in this layer claimed leakage-free"),
    }
    manifest["exploratory_holdout"] = {
        "tasks_file": f"benchmark/independent/{EXPLORATORY_TASKS_NAME}",
        "rows": len(exploratory_tasks),
        "contaminated_rows": len(contaminated_ids),
        "clean_rows_excluded_with_family": sum(
            family_excluded_by_family.values()),
        "by_family": dict(sorted(collections.Counter(
            t["family_file"] for t in exploratory_tasks).items())),
        "contaminated_by_family": dict(sorted(contaminated_by_family.items())),
        "claim": (
            "these rows are EXPLORATORY. Their model-facing payload carries "
            "the answer literal because the source family's evidence names "
            "it. They are not independent, not leakage-free and must not be "
            "reported as holdout evidence"),
    }
    manifest["payload_answer_literal_overlap"] = {
        "definition": (
            "word-boundary literal occurrence of the gold scalar in "
            "evidence_text(input), the audit's model-facing evidence: "
            "instruction scaffolding (prompt, class_vocabulary, taxonomy, "
            "tier_rules, prompt_to_answer) and nested prompt/question keys "
            "are excluded because they describe the label space to every "
            "row"),
        "rows_held_out_total": len(tasks) + len(exploratory_tasks),
        "rows_with_overlap_before": sum(overlap_before.values()),
        "by_family_before": dict(sorted(
            (f, n) for f, n in overlap_before.items() if n)),
        "rows_transformed_and_clean": sum(transformed_by_family.values()),
        "by_family_transformed": dict(sorted(transformed_by_family.items())),
        "rows_excluded_contaminated": len(contaminated_ids),
        "by_family_excluded_contaminated": dict(
            sorted(contaminated_by_family.items())),
        "rows_excluded_with_family_clean": sum(
            family_excluded_by_family.values()),
        "by_family_excluded_with_family_clean": dict(
            sorted(family_excluded_by_family.items())),
        "rows_in_clean_holdout": len(tasks),
        "rows_in_exploratory_holdout": len(exploratory_tasks),
        "rows_with_overlap_after_in_clean_holdout": clean_leaks,
        "contaminated_task_ids": contaminated_ids,
        "exploratory_task_ids": exploratory_ids,
        "claim": (
            "the clean holdout contains zero rows with a known literal-answer "
            "overlap. Contaminated rows remain only in the exploratory file ("
            + ", ".join(f"{f}: {n}" for f, n in
                        sorted(contaminated_by_family.items()))
            + ") and are not clean, independent or leakage-free"),
        "families_excluded_from_clean": dict(sorted(
            (f, r) for f, r in EXCLUDED_FAMILIES.items())),
        "families_transformed_for_clean": dict(sorted(
            (f, r) for f, r in TRANSFORM_FAMILIES.items())),
    }
    manifest["transforms"] = sorted(
        transforms, key=lambda t: (t["family_file"], t["holdout"],
                                   t["holdout_task_id"], t["field"]))
    manifest["tasks_written"] = len(tasks)
    manifest["keys_written"] = len(keys)
    manifest["exploratory_tasks_written"] = len(exploratory_tasks)
    manifest["exploratory_keys_written"] = len(exploratory_keys)
    return manifest, tasks, keys, exploratory_tasks, exploratory_keys


def build(seed: int, min_minority: int) -> tuple[dict, list[dict]]:
    """The manifest and the CLEAN model-facing task rows."""
    manifest, tasks, _keys, _et, _ek = _build(seed, min_minority)
    return manifest, tasks


# ---------------------------------------------------------------------------
# Verification from the written files (never trusts manifest prose, never
# reads the answer key)
# ---------------------------------------------------------------------------

def _task_source_map() -> dict[str, tuple[str, str, dict]]:
    """task id -> (family, holdout, source row), rebuilt from committed files."""
    out: dict[str, tuple[str, str, dict]] = {}
    for fname in sorted(_audit.FAMILIES):
        if fname in _audit.NOT_SCORABLE:
            continue
        spec = _audit.FAMILIES[fname]
        for row in _audit.scorable_rows(fname, _audit.load_family(fname)):
            original_id = _audit.task_id(row, spec["id"])
            for holdout in PARTITIONS:
                out[task_pseudonym(fname, holdout, original_id)] = (
                    fname, holdout, row)
    return out


def _read_jsonl(path: pathlib.Path) -> list[dict]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in
            path.read_text(encoding="utf-8").splitlines() if line.strip()]


def verify_written_holdout() -> dict:
    """Recompute the leakage claims from the written files and sources.

    Returns {"errors": [...], counts...}. An empty error list means every
    row in the clean task file has zero known literal-answer overlap, every
    task row has only model-facing fields, and the manifest's before/after
    counts match the files. The answer key is never read.
    """
    manifest = json.loads((OUT_DIR / MANIFEST_NAME).read_text(encoding="utf-8"))
    tasks = _read_jsonl(OUT_DIR / TASKS_NAME)
    exploratory = _read_jsonl(OUT_DIR / EXPLORATORY_TASKS_NAME)
    smap = _task_source_map()
    errors: list[str] = []
    task_by_id = {t.get("holdout_task_id"): t for t in tasks}
    source_leaks = 0
    clean_leaks = 0
    transformed = 0
    contaminated: list[str] = []
    exploratory_ids: list[str] = []
    transform_ids = {tr.get("holdout_task_id")
                     for tr in manifest.get("transforms", [])}

    def check_row(row: dict, label: str) -> tuple | None:
        tid = row.get("holdout_task_id")
        extra = set(row) - set(TASK_FIELDS)
        if extra:
            errors.append(f"{label} task {tid!r} carries non-task fields "
                          f"{sorted(extra)}")
        if tid not in smap:
            errors.append(f"{label} task {tid!r} does not join to any "
                          f"committed scorable row")
            return None
        fname, holdout, src = smap[tid]
        if row.get("family_file") != fname or row.get("holdout") != holdout:
            errors.append(f"{label} task {tid!r} family/holdout mismatch")
        return fname, holdout, src

    for row in tasks:
        joined = check_row(row, "clean")
        if joined is None:
            continue
        fname, _holdout, src = joined
        gold = _audit.gold_of(src, _audit.FAMILIES[fname]["projection"])
        if find_answer_leaks(src.get("input"), gold):
            source_leaks += 1
            if not find_answer_leaks(row.get("input"), gold):
                transformed += 1
                if row["holdout_task_id"] not in transform_ids:
                    errors.append(
                        f"clean task {row['holdout_task_id']!r} was "
                        f"transformed but has no manifest provenance record")
            else:
                errors.append(
                    f"clean task {row['holdout_task_id']!r} still carries "
                    f"its answer literal")
        if find_answer_leaks(row.get("input"), gold):
            clean_leaks += 1
    for row in exploratory:
        joined = check_row(row, "exploratory")
        exploratory_ids.append(row.get("holdout_task_id"))
        if joined is None:
            continue
        fname, _holdout, src = joined
        gold = _audit.gold_of(src, _audit.FAMILIES[fname]["projection"])
        if find_answer_leaks(src.get("input"), gold):
            source_leaks += 1
            if find_answer_leaks(row.get("input"), gold):
                contaminated.append(row["holdout_task_id"])
            else:
                errors.append(
                    f"exploratory task {row['holdout_task_id']!r} is not "
                    f"leaking; it belongs in the clean partition")

    for tr in manifest.get("transforms", []):
        tid = tr.get("holdout_task_id")
        if tid not in task_by_id or tid not in smap:
            errors.append(f"transform for unknown task {tid!r}")
            continue
        src = smap[tid][2]
        try:
            before = _leaf_at(src.get("input"), tr["field"])
            after = _leaf_at(task_by_id[tid].get("input"), tr["field"])
        except (KeyError, IndexError, TypeError):
            errors.append(f"transform field {tr.get('field')!r} missing for "
                          f"task {tid!r}")
            continue
        if _sha256(before) != tr.get("before_sha256"):
            errors.append(f"transform before-hash mismatch for {tid!r} "
                          f"{tr.get('field')!r}")
        if _sha256(after) != tr.get("after_sha256"):
            errors.append(f"transform after-hash mismatch for {tid!r} "
                          f"{tr.get('field')!r}")
        if tr.get("rule") != REDACTION_RULE:
            errors.append(f"unknown transform rule {tr.get('rule')!r}")
        if before == after:
            errors.append(f"transform did not change {tid!r} "
                          f"{tr.get('field')!r}")

    expected = {
        "tasks": len(tasks),
        "exploratory": len(exploratory),
        "rows_with_overlap_before": source_leaks,
        "rows_with_overlap_after_in_clean_holdout": clean_leaks,
        "rows_transformed_and_clean": transformed,
        "rows_excluded_contaminated": len(contaminated),
    }
    claims = manifest.get("payload_answer_literal_overlap", {})
    pairs = (
        ("rows_in_clean_holdout", expected["tasks"]),
        ("rows_in_exploratory_holdout", expected["exploratory"]),
        ("rows_with_overlap_before", expected["rows_with_overlap_before"]),
        ("rows_with_overlap_after_in_clean_holdout",
         expected["rows_with_overlap_after_in_clean_holdout"]),
        ("rows_transformed_and_clean", expected["rows_transformed_and_clean"]),
        ("rows_excluded_contaminated", expected["rows_excluded_contaminated"]),
    )
    for name, actual in pairs:
        if claims.get(name) != actual:
            errors.append(
                f"manifest {name}={claims.get(name)!r} but recomputation "
                f"gives {actual!r}")
    if set(claims.get("contaminated_task_ids", [])) != set(contaminated):
        errors.append("manifest contaminated_task_ids does not match the "
                      "recomputation")
    if set(claims.get("exploratory_task_ids", [])) != set(exploratory_ids):
        errors.append("manifest exploratory_task_ids does not match the "
                      "task file")
    if clean_leaks:
        errors.append(f"{clean_leaks} row(s) in the clean holdout carry "
                      f"their answer literal")
    return {**expected, "errors": errors}


# ---------------------------------------------------------------------------
# Rendering and CLI
# ---------------------------------------------------------------------------

def rendered_files(seed: int, min_minority: int) -> dict[pathlib.Path, str]:
    manifest, tasks, keys, exploratory_tasks, exploratory_keys = _build(
        seed, min_minority)
    leaked = sorted({f for t in tasks + exploratory_tasks
                     for f in ANSWER_FIELDS if f in t})
    if leaked:
        raise SystemExit("model-facing task rows carry answer material: "
                         + ", ".join(leaked))
    return {
        OUT_DIR / MANIFEST_NAME:
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        OUT_DIR / TASKS_NAME:
            "".join(json.dumps(t, sort_keys=True, ensure_ascii=False) + "\n"
                    for t in tasks),
        OUT_DIR / KEYS_NAME:
            "".join(json.dumps(k, sort_keys=True, ensure_ascii=False) + "\n"
                    for k in keys),
        OUT_DIR / EXPLORATORY_TASKS_NAME:
            "".join(json.dumps(t, sort_keys=True, ensure_ascii=False) + "\n"
                    for t in exploratory_tasks),
        OUT_DIR / EXPLORATORY_KEYS_NAME:
            "".join(json.dumps(k, sort_keys=True, ensure_ascii=False) + "\n"
                    for k in exploratory_keys),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--min-minority", type=int, default=5)
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    rendered = rendered_files(args.seed, args.min_minority)
    if args.check:
        bad = []
        for path, want in rendered.items():
            if path.name in (KEYS_NAME, EXPLORATORY_KEYS_NAME):
                # The key is local-only and untracked; a checkout/CI without
                # it is the expected state, not a failure.
                if path.is_file() and path.read_text(
                        encoding="utf-8") != want:
                    bad.append(f"STALE local key {path}")
                continue
            if not path.is_file():
                bad.append(f"missing {path}")
            elif path.read_text(encoding="utf-8") != want:
                bad.append(f"STALE {path}")
        verification = verify_written_holdout()
        bad.extend(verification["errors"])
        if bad:
            print("; ".join(bad) + " -- run: python "
                  "scripts/build_secondary_holdout.py", file=sys.stderr)
            return 1
        key_state = ("present locally" if (OUT_DIR / KEYS_NAME).is_file()
                     else "absent locally (untracked, not required)")
        print("secondary holdout is current: "
              f"{verification['tasks']} clean rows with zero literal "
              f"overlap, {verification['exploratory']} exploratory rows "
              f"({verification['rows_excluded_contaminated']} contaminated); "
              f"answer key {key_state}")
        return 0
    for path, text in rendered.items():
        path.write_text(text, encoding="utf-8", newline="\n")
    manifest = json.loads(rendered[OUT_DIR / MANIFEST_NAME])
    verification = verify_written_holdout()
    print(f"wrote {OUT_DIR / MANIFEST_NAME}")
    print(f"wrote {OUT_DIR / TASKS_NAME} "
          f"({manifest['tasks_written']} clean model-facing tasks, "
          f"zero literal-answer overlap)")
    print(f"wrote {OUT_DIR / EXPLORATORY_TASKS_NAME} "
          f"({manifest['exploratory_tasks_written']} exploratory tasks; "
          f"{manifest['payload_answer_literal_overlap']['rows_excluded_contaminated']} "
          f"contaminated)")
    print(f"wrote {OUT_DIR / KEYS_NAME} and {OUT_DIR / EXPLORATORY_KEYS_NAME} "
          f"(local-only, untracked)")
    built = sum(1 for v in manifest["families"].values()
                if v.get("class_disjoint", {}).get("verdict") == "built")
    skipped = sum(1 for v in manifest["families"].values()
                  if v.get("class_disjoint", {}).get("verdict", "").startswith(
                      "skipped"))
    print(f"class-disjoint clean for {built} families; skipped for {skipped}")
    if verification["errors"]:
        for err in verification["errors"]:
            print("VERIFY: " + err, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
