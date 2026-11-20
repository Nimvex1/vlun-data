"""assign_group_splits.py -- deterministic, group-disjoint Wave-1 splits.

Purpose
-------
The pre-existing Wave-1 benchmark splits leak whole source groups across
train/val/test (e.g. all 11 mitigation contests in G_patch_verification appear
in every split). VLUN treats cross-split group overlap as INVALID. This script
recomputes `group_id` and `split` for EVERY row of EVERY family JSONL in
wave1/benchmark_wave1/, keeping a whole group inside exactly one split.

Design contract
---------------
* stdlib only; writes are confined to wave1/ via _common.guard_wave1().
* deterministic + idempotent: the assignment is derived only from each group's
  stable identity, size and label multiset, never from the old `split` value.
  Re-running produces byte-identical outputs (no timestamps, no RNG).
* every row keeps all of its original fields; only `group_id` is added/updated
  and `split` is reassigned. No rows are fabricated or removed.

Group identity rules (as specified by STAGE 4 FIX 1)
----------------------------------------------------
* G_patch_verification, severity_reconciliation, J_verified_patch,
  prove_candidates: group_id = normalised repo_slug.
* F_false_positive_rejection, Fa_rejection_evidence_axis_vector:
  group_id = normalised contest slug.
* Fb_duplicate_radar_pair: group_id = canonical contest-pair slug built from
  the row's `contest` field ("contestA|contestB" -> sorted, de-duplicated,
  normalised, re-joined with "|"). This is the contest-derived group key for a
  pair task: the pair slug is the indivisible unit, so both sides of a finding
  pair are always kept in the same split.
* invariants: group_id = sha256(repo_slug + '|' + contract_or_spec_file + '|'
  + base_property_stem)[:16]. The stem is derived from candidate_id's
  `<repo>:<spec>:<rule_id>:<line>` shape by taking the rule_id field and
  stripping trailing colon-delimited line numbers / verdict-variant tokens
  (Original, m1..mN, mutantN, clean). Only colon-delimited suffixes are
  stripped; underscores that are part of a rule name (e.g.
  `handleRepaymentCorrectness_conditionalSatisfiability1`) are preserved.
  The line number is therefore never part of the group key.
* prove_incidents (no repo_slug/contest): group_id = normalised candidate_id,
  which is the incident's stable harness identifier.

Assignment rule
---------------
For each family, groups are sorted by (-row_count, -label_count, group_id)
and placed with a best-fit greedy against 70/15/15 targets, then improved by
deterministic one-group hill climbing. Families with <=12 groups are solved
exactly by bounded exhaustive search (3**12 assignments) so the whole-group
optimum under the floor constraints is found; larger families use the greedy
+ hill-climb path. Floor constraints: val and test each get >=30 rows and >=2
labels whenever that is achievable with whole groups and a non-empty train.
A group is NEVER split to reach a target or a floor. If a family cannot meet
the floors with whole groups, it keeps the best honest assignment and a
`demotion_reason` is recorded in the report.
"""
from __future__ import annotations

import hashlib
import re
from collections import Counter
from itertools import product
from pathlib import Path
from typing import Any

# Import from the sibling helper module (works both as a script and via -m
# style invocation because Python puts the script's directory on sys.path).
from _common import (
    WAVE1,
    guard_wave1,
    norm_repo_slug,
    read_jsonl,
    write_json,
    write_jsonl,
)

SPLITS = ("train", "val", "test")
TARGET_FRACTIONS = (0.70, 0.15, 0.15)
MIN_HOLDOUT_ROWS = 30
MIN_HOLDOUT_LABELS = 2
EXHAUSTIVE_GROUP_LIMIT = 12

REPO_SLUG_FAMILIES = frozenset({
    "G_patch_verification",
    "severity_reconciliation",
    "J_verified_patch",
    "prove_candidates",
})
CONTEST_FAMILIES = frozenset({
    "F_false_positive_rejection",
    "Fa_rejection_evidence_axis_vector",
})
PAIR_FAMILIES = frozenset({"Fb_duplicate_radar_pair"})
INVARIANT_FAMILIES = frozenset({"invariants"})

_VARIANT_TOKEN = re.compile(r"^(?:original|clean|m\d+|mutant\d+)$", re.I)


# --------------------------------------------------------------------------
# group identity
# --------------------------------------------------------------------------
def norm_contest(value: Any) -> str:
    """Normalise a contest slug (case/whitespace only, no URL rewriting)."""
    return str(value or "").strip().lower()


def base_property_stem(candidate_id: Any, rule_id: Any = None) -> str:
    """Return the base property stem from a candidate_id / rule_id.

    Candidate ids in the invariants family look like
    ``<repo>:<spec_file>:<rule_id>:<line_number>``. The rule_id field is taken
    verbatim and only trailing *colon-delimited* tokens are removed when they
    are a pure line number or a known verdict variant (Original, m7, ...).
    A trailing underscore-suffixed rule name is part of the property identity
    and is deliberately preserved. The result is deterministic and stable.
    """
    raw = str(rule_id or "").strip()
    if not raw:
        parts = str(candidate_id or "").split(":")
        if len(parts) >= 3:
            raw = parts[2].strip()
        elif parts:
            raw = parts[-1].strip()
    tokens = raw.split(":")
    while tokens and (tokens[-1].isdigit() or _VARIANT_TOKEN.match(tokens[-1])):
        tokens.pop()
    return ":".join(tokens).strip() or raw


def invariant_group_id(row: dict) -> str:
    """sha256(repo|spec|base_property_stem)[:16] for a formal-property row."""
    cid = str(row.get("candidate_id") or "")
    parts = cid.split(":")
    repo = str(row.get("repo_slug") or (parts[0] if parts else "")).strip()
    spec = str(
        row.get("contract_or_spec_file")
        or row.get("spec_file")
        or (parts[1] if len(parts) >= 2 else "")
    ).strip()
    stem = base_property_stem(cid, row.get("rule_id"))
    key = f"{repo}|{spec}|{stem}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def group_id_for(family: str, row: dict) -> str:
    """Compute the stable group key of a row in the given family."""
    if family in INVARIANT_FAMILIES:
        return invariant_group_id(row)
    if family in REPO_SLUG_FAMILIES:
        slug = norm_repo_slug(str(row.get("repo_slug") or ""))
        if slug:
            return slug
    if family in CONTEST_FAMILIES:
        contest = norm_contest(row.get("contest"))
        if contest:
            return contest
    if family in PAIR_FAMILIES:
        parts = [norm_contest(p) for p in str(row.get("contest") or "").split("|")]
        parts = sorted({p for p in parts if p})
        if parts:
            return "|".join(parts)
    # Generic, deterministic fallback for the non-scorable provenance files.
    candidate = str(row.get("candidate_id") or "").strip()
    if candidate:
        return candidate
    raise ValueError(f"{family}: row has no usable group key: {row!r}")


# --------------------------------------------------------------------------
# assignment
# --------------------------------------------------------------------------
def targets_for(n: int) -> list[int]:
    """Integer 70/15/15 row targets summing exactly to n."""
    if n <= 0:
        return [0, 0, 0]
    val = int(round(TARGET_FRACTIONS[1] * n))
    train = int(round(TARGET_FRACTIONS[0] * n))
    return [train, val, n - train - val]


def cost_of(
    row_counts: list[int],
    label_sets: list[set[str]],
    targets: list[int],
    global_labels: set[str],
    apply_floor: bool = True,
) -> float:
    """Lower is better.

    The dominant term is the squared relative deviation from the 70/15/15
    targets. Hold-out floors carry a *deliberately modest* soft penalty: it is
    strong enough to choose a floor-satisfying whole-group assignment when one
    exists at comparable ratio error (e.g. F_false_positive_rejection), but it
    can never collapse train into a 1-row token split just to satisfy a floor
    (e.g. severity_reconciliation / Fa, where genuine group-disjointness makes
    that trade dishonest). Train is additionally required to be non-empty and
    at least as large as either hold-out split.
    """
    cost = 0.0
    for idx, target in enumerate(targets):
        denom = target if target > 0 else 1
        delta = (row_counts[idx] - target) / denom
        cost += delta * delta
    if (
        row_counts[0] <= 0
        or row_counts[0] < row_counts[1]
        or row_counts[0] < row_counts[2]
    ):
        cost += 1000.0
    if apply_floor:
        need_labels = len(global_labels) >= MIN_HOLDOUT_LABELS
        for idx in (1, 2):
            if row_counts[idx] < MIN_HOLDOUT_ROWS:
                cost += 1.0 * (MIN_HOLDOUT_ROWS - row_counts[idx])
            if need_labels and len(label_sets[idx]) < MIN_HOLDOUT_LABELS:
                cost += 2.0
    return cost


def floors_met(row_counts: list[int], label_sets: list[set[str]], global_labels: set[str]) -> bool:
    """True when both held-out splits meet the floors and train stays non-empty."""
    if row_counts[0] <= 0:
        return False
    if row_counts[1] < MIN_HOLDOUT_ROWS or row_counts[2] < MIN_HOLDOUT_ROWS:
        return False
    if len(global_labels) >= MIN_HOLDOUT_LABELS:
        if len(label_sets[1]) < MIN_HOLDOUT_LABELS or len(label_sets[2]) < MIN_HOLDOUT_LABELS:
            return False
    return True


class Group:
    __slots__ = ("gid", "rows", "size", "labels", "label_counts")

    def __init__(self, gid: str, rows: list[dict]):
        self.gid = gid
        self.rows = rows
        self.size = len(rows)
        self.label_counts = Counter(str(r.get("label")) for r in rows if r.get("label") is not None)
        self.labels = frozenset(self.label_counts)


def order_for_search(groups: list[Group]) -> list[int]:
    return sorted(
        range(len(groups)),
        key=lambda i: (-groups[i].size, -len(groups[i].labels), groups[i].gid),
    )


def solve_exhaustive(
    groups: list[Group], targets: list[int], global_labels: set[str], apply_floor: bool = True
) -> list[int]:
    """Exact 3-way search for small families; minimum-cost whole-group split."""
    k = len(groups)
    sizes = [g.size for g in groups]
    label_sets = [g.labels for g in groups]
    best_cost = float("inf")
    best: list[int] | None = None

    for combo in product(range(3), repeat=k):
        counts = [0, 0, 0]
        labs: list[set[str]] = [set(), set(), set()]
        for idx, split in enumerate(combo):
            counts[split] += sizes[idx]
            labs[split].update(label_sets[idx])
        cost = cost_of(counts, labs, targets, global_labels, apply_floor)
        # Strict improvement only: with a deterministic combo order this keeps
        # the first (and therefore reproducible) optimum.
        if cost < best_cost - 1e-12:
            best_cost, best = cost, list(combo)
    assert best is not None
    return best


def balance_penalty(label_counters: list[Counter], row_counts: list[int]) -> float:
    """Discourage a hold-out set dominated by the train majority label.

    This mirrors the PRIMARY shortcut gate (majority train label accuracy on
    test must be < 0.9) and only steers *whole-group* placement; it never
    splits a group to manufacture balance.
    """
    train = label_counters[0]
    if not train or row_counts[2] == 0:
        return 0.0
    majority, _ = train.most_common(1)[0]
    frac = label_counters[2].get(majority, 0) / row_counts[2]
    if frac > 0.85:
        return 20.0 * (frac - 0.85) + 2.0
    return 0.0


def solve_large(
    groups: list[Group], targets: list[int], global_labels: set[str], apply_floor: bool = True
) -> list[int]:
    """Deterministic best-fit greedy + one-group hill climbing for big families."""
    k = len(groups)
    sizes = [g.size for g in groups]
    g_labels = [g.labels for g in groups]
    g_counts = [g.label_counts for g in groups]
    order = order_for_search(groups)

    counts = [0, 0, 0]
    labs: list[set[str]] = [set(), set(), set()]
    lab_counts: list[Counter] = [Counter(), Counter(), Counter()]
    assign = [0] * k

    def total_cost(rc: list[int], ls: list[set[str]], lc: list[Counter]) -> float:
        return cost_of(rc, ls, targets, global_labels, apply_floor) + balance_penalty(lc, rc)

    for idx in order:
        best: tuple[float, int, list[int], list[set[str]], list[Counter]] | None = None
        for split in range(3):
            trial_counts = list(counts)
            trial_labs = [set(s) for s in labs]
            trial_lc = [Counter(c) for c in lab_counts]
            trial_counts[split] += sizes[idx]
            trial_labs[split].update(g_labels[idx])
            trial_lc[split].update(g_counts[idx])
            cost = total_cost(trial_counts, trial_labs, trial_lc)
            if best is None or cost < best[0] - 1e-12:
                best = (cost, split, trial_counts, trial_labs, trial_lc)
        assert best is not None
        _, split, counts, labs, lab_counts = best
        assign[idx] = split

    current = total_cost(counts, labs, lab_counts)
    # Deterministic local improvement: try moving each group to another split.
    for _ in range(200):
        improved = False
        for idx in order:
            src = assign[idx]
            for dst in range(3):
                if dst == src:
                    continue
                trial_counts = list(counts)
                trial_labs = [set(s) for s in labs]
                trial_lc = [Counter(c) for c in lab_counts]
                trial_counts[src] -= sizes[idx]
                trial_counts[dst] += sizes[idx]
                trial_lc[dst].update(g_counts[idx])
                # Rebuild the donor's label multiset from scratch: cheap for
                # these family sizes and avoids incremental bookkeeping bugs.
                trial_labs[src] = set()
                trial_lc[src] = Counter()
                for j in range(k):
                    if j == idx or assign[j] != src:
                        continue
                    trial_labs[src].update(g_labels[j])
                    trial_lc[src].update(g_counts[j])
                cost = total_cost(trial_counts, trial_labs, trial_lc)
                if cost < current - 1e-9:
                    assign[idx] = dst
                    counts, labs, lab_counts, current = trial_counts, trial_labs, trial_lc, cost
                    improved = True
                    break
            if improved:
                break
        if not improved:
            break

    return assign


def primary_readiness(rows: list[dict]) -> dict:
    """Mirror validate_wave1.gate_e_benchmark on the reassigned rows."""
    scorable = [r for r in rows if r.get("answer") is not None and r.get("label") is not None]
    labels = {str(r.get("label")) for r in scorable}
    splits = Counter(str(r.get("split")) for r in scorable)
    test_n = splits.get("test", 0) + splits.get("holdout", 0)
    train_labels: dict[str, Counter] = {}
    for row in scorable:
        if str(row.get("split")) in ("train", "trainval"):
            fam = str(row.get("family", "all"))
            train_labels.setdefault(fam, Counter())[str(row.get("label"))] += 1
    shortcut = None
    if train_labels and test_n:
        majority = None
        for counter in train_labels.values():
            if counter:
                majority = majority or counter.most_common(1)[0][0]
        if majority:
            correct = sum(
                1 for r in scorable
                if str(r.get("split")) in ("test", "holdout") and str(r.get("label")) == majority
            )
            shortcut = round(correct / test_n, 4)
    ready = (
        len(scorable) >= 100
        and len(labels) >= 2
        and test_n >= 30
        and (shortcut is None or shortcut < 0.9)
    )
    reasons = []
    if len(scorable) < 100:
        reasons.append(f"scorable_rows={len(scorable)} < 100")
    if len(labels) < 2:
        reasons.append(f"observed_labels={sorted(labels)} < 2")
    if test_n < 30:
        reasons.append(f"test_rows={test_n} < 30")
    if shortcut is not None and shortcut >= 0.9:
        reasons.append(f"train_shortcut={shortcut} >= 0.9")
    return {
        "scorable_rows": len(scorable),
        "observed_labels": sorted(labels),
        "test_rows": test_n,
        "train_shortcut": shortcut,
        "primary_ready": ready,
        "primary_blockers": reasons,
    }


def demotion_reason_for(
    family: str,
    groups: list[Group],
    floor_ok: bool,
    rows: list[dict],
) -> str | None:
    """Explain why a family cannot be PRIMARY after group-disjoint splitting."""
    reasons: list[str] = []
    if not rows:
        return "family file is empty (no rows to split)"
    n = len(rows)
    biggest = max((g.size for g in groups), default=0)
    scorable = [r for r in rows if r.get("answer") is not None and r.get("label") is not None]
    if not floor_ok and scorable:
        reasons.append(
            "group-disjoint whole-group assignment cannot give BOTH val and test "
            f">={MIN_HOLDOUT_ROWS} rows and >={MIN_HOLDOUT_LABELS} labels "
            f"({len(groups)} groups over {n} rows; largest group has {biggest} rows)"
        )
    if not scorable:
        reasons.append("non-scorable provenance family (no answer/label rows)")
    readiness = primary_readiness(rows)
    reasons.extend(readiness["primary_blockers"])
    return "; ".join(dict.fromkeys(reasons)) if reasons else None


# --------------------------------------------------------------------------
# driver
# --------------------------------------------------------------------------
def assign_family(family: str, path: Path) -> tuple[list[dict], dict]:
    rows = list(read_jsonl(guard_wave1(path)))
    by_gid: dict[str, list[dict]] = {}
    gids: list[str] = []
    row_group_index: list[int] = []
    gid_to_index: dict[str, int] = {}
    for row in rows:
        gid = group_id_for(family, row)
        if gid not in by_gid:
            by_gid[gid] = []
            gids.append(gid)
            gid_to_index[gid] = len(gids) - 1
        row_group_index.append(gid_to_index[gid])
        by_gid[gid].append(row)

    groups = [Group(gid, by_gid[gid]) for gid in gids]
    n = len(rows)
    targets = targets_for(n)
    global_labels = {str(r.get("label")) for r in rows if r.get("label") is not None}
    # Non-scorable provenance files carry no labels/answers: hold-out floors
    # are meaningless there, so only the 70/15/15 ratio term applies.
    apply_floor = bool(global_labels)

    if not groups:
        assign: list[int] = []
    elif len(groups) <= EXHAUSTIVE_GROUP_LIMIT:
        assign = solve_exhaustive(groups, targets, global_labels, apply_floor)
    else:
        assign = solve_large(groups, targets, global_labels, apply_floor)

    group_split = [SPLITS[assign[i]] for i in range(len(groups))]
    out_rows: list[dict] = []
    for row, gidx in zip(rows, row_group_index):
        new_row = dict(row)
        new_row["group_id"] = groups[gidx].gid
        new_row["split"] = group_split[gidx]
        out_rows.append(new_row)

    # Exact input row order is preserved: only group_id/split are touched.
    assert len(out_rows) == n

    counts = [0, 0, 0]
    label_sets: list[set[str]] = [set(), set(), set()]
    label_counts: list[Counter] = [Counter(), Counter(), Counter()]
    for group, split_idx in zip(groups, assign):
        counts[split_idx] += group.size
        label_sets[split_idx].update(group.labels)
        label_counts[split_idx].update(group.label_counts)
    floor_ok = floors_met(counts, label_sets, global_labels)

    group_to_splits: dict[str, set[str]] = {}
    for row in out_rows:
        group_to_splits.setdefault(str(row["group_id"]), set()).add(str(row["split"]))
    disjoint = all(len(s) == 1 for s in group_to_splits.values())

    report_entry = {
        "rows": n,
        "groups": len(groups),
        "group_rule": (
            "invariants: sha256(repo|spec|base_property_stem)[:16]"
            if family in INVARIANT_FAMILIES
            else "contest_pair slug from 'contest'"
            if family in PAIR_FAMILIES
            else "contest slug"
            if family in CONTEST_FAMILIES
            else "repo_slug"
            if family in REPO_SLUG_FAMILIES
            else "candidate_id fallback"
        ),
        "target_rows": dict(zip(SPLITS, targets)),
        "rows_per_split": dict(zip(SPLITS, counts)),
        "label_distribution_per_split": {
            split: dict(sorted(label_counts[i].items())) for i, split in enumerate(SPLITS)
        },
        "labels_per_split": {
            split: sorted(label_sets[i]) for i, split in enumerate(SPLITS)
        },
        "largest_group_rows": max((g.size for g in groups), default=0),
        "group_disjoint": disjoint,
        "group_overlap_count": sum(1 for s in group_to_splits.values() if len(s) > 1),
        "floors_met": floor_ok,
        "demotion_reason": demotion_reason_for(family, groups, floor_ok, out_rows),
        "primary_readiness": primary_readiness(out_rows),
    }
    return out_rows, report_entry


def verify_all(paths: list[Path]) -> dict:
    """Read-only re-check of every family after writing."""
    families: dict[str, dict] = {}
    all_disjoint = True
    for path in paths:
        group_to_splits: dict[str, set[str]] = {}
        splits_seen: set[str] = set()
        rows = 0
        for row in read_jsonl(guard_wave1(path)):
            rows += 1
            gid = row.get("group_id")
            split = row.get("split")
            if not gid or not split:
                raise AssertionError(f"{path.name}: row {rows} missing group_id/split")
            group_to_splits.setdefault(str(gid), set()).add(str(split))
            splits_seen.add(str(split))
        overlap = {g: sorted(s) for g, s in group_to_splits.items() if len(s) > 1}
        if overlap:
            all_disjoint = False
        families[path.stem] = {
            "rows": rows,
            "groups": len(group_to_splits),
            "splits": sorted(splits_seen),
            "groups_with_multiple_splits": overlap,
            "group_disjoint": not overlap,
        }
    if not all_disjoint:
        raise AssertionError("group-disjointness verification FAILED")
    return {"all_families_group_disjoint": all_disjoint, "families": families}


def main() -> None:
    bdir = guard_wave1(WAVE1 / "benchmark_wave1")
    paths = sorted(bdir.glob("*.jsonl"))
    report: dict[str, Any] = {
        "method": {
            "group_rules": {
                "repo_slug_families": sorted(REPO_SLUG_FAMILIES),
                "contest_families": sorted(CONTEST_FAMILIES),
                "contest_pair_families": sorted(PAIR_FAMILIES),
                "sha256_property_families": sorted(INVARIANT_FAMILIES),
                "invariants_formula": "sha256(repo_slug + '|' + spec_file + '|' + base_property_stem)[:16]",
                "base_property_stem": (
                    "rule_id field of candidate_id with trailing colon-delimited "
                    "line numbers / verdict variants stripped; underscore-suffixed "
                    "rule names preserved; line number never part of the key"
                ),
            },
            "target_split_fractions": dict(zip(SPLITS, TARGET_FRACTIONS)),
            "min_holdout_rows": MIN_HOLDOUT_ROWS,
            "min_holdout_labels": MIN_HOLDOUT_LABELS,
            "search": (
                f"exact 3-way search for <= {EXHAUSTIVE_GROUP_LIMIT} groups; "
                "deterministic size/label-sorted greedy + hill climbing above that; "
                "whole groups only, never split"
            ),
            "idempotent": True,
        },
        "families": {},
    }

    for path in paths:
        family = path.stem
        out_rows, entry = assign_family(family, path)
        if not entry["group_disjoint"]:
            raise AssertionError(f"{family}: internal group-disjointness check failed")
        write_jsonl(guard_wave1(path), out_rows)
        report["families"][family] = entry
        print(f"[{family}] groups={entry['groups']} rows={entry['rows']} "
              f"split={entry['rows_per_split']} floors_met={entry['floors_met']}")

    report["verification"] = verify_all(paths)
    demoted = [
        name for name, entry in report["families"].items()
        if entry["demotion_reason"] is not None
        or not entry["primary_readiness"]["primary_ready"]
    ]
    report["families_not_primary_after_group_disjoint"] = demoted

    report_path = guard_wave1(WAVE1 / "reports_wave1" / "group_split_report.json")
    write_json(report_path, report)
    print(f"[assign_group_splits] wrote {report_path}")
    print(f"[assign_group_splits] verified {len(paths)} family files, all group-disjoint")
    if demoted:
        print("[assign_group_splits] NOT PRIMARY: " + ", ".join(demoted))


if __name__ == "__main__":
    main()
