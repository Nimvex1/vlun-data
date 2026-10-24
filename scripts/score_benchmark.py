#!/usr/bin/env python3
"""Exact-match scorer for VLUN benchmark families.

Compares a predictions file against answer keys and reports per-family plus
micro-averaged accuracy. Writes nothing unless --out/--md is given.

Predictions file (JSONL, one row per task):
    {"task_id": "<family file id/task_id>", "answer": "<model answer>"}

Scoring rule: the model's answer, lowercased and stripped, must equal the
projected scalar from the answer key. Only tasks with answer_key_status ==
"labeled" are scored; anything else is reported unscorable, never guessed.

WHICH FAMILIES COUNT
--------------------
The headline is not a list of file names. `scripts/benchmark_status.py`
computes a status for every family from the independent audit's own
measurements (`scripts/independent_benchmark_audit.py`), recomputed live:

    PRIMARY      no validity flag, enough rows, at least two labels, no
                 train-only shortcut that solves the held-out split. Only
                 these families enter the headline micro-average, and the
                 headline carries its own denominator.
    EXPLORATORY  shipped and scored, but demoted: too small, holdout too
                 small, or a single observed label. Reported per family and
                 per status; never in the headline.
    INVALID      a validity flag makes the family unusable as evaluation
                 evidence (answer leak, split drift, held-out labels unseen
                 in train, group/record overlap, near-duplicate leak,
                 saturation, shortcut domination). Its rows stay in the
                 dataset and stay scored; they are reported in their own
                 block, never in the headline.
    NOT_SCORABLE no exactly-matchable scalar key (D generative, H
                 descriptive, Q judge-graded) OR a registered family with no
                 published scorer yet (the F-extension: Fa's gold is a
                 six-axis vector, Fb's three-class pair relation is not yet
                 promoted) -- reported with the reason, never zero-filled.
    UNKNOWN      a family file on disk that no rule covers: fail-closed,
                 never primary.

A family whose scorable rows carry exactly one observed label is NOT
EVALUABLE for accuracy: its accuracy is null with a stated reason
("single_label_not_evaluable"), in every block, including the exploratory
tables. A single observed label makes any accuracy a restatement of the
label distribution, so publishing 1.000 for one would be publishing the
label distribution as predictive performance.

BASELINES (deterministic, reproducible)
---------------------------------------
Every baseline that acts as a test-set floor is fitted on TRAIN ROWS ONLY
and applied to the held-out rows. A majority predictor fitted on every
labelled row (held-out rows included) is not a valid floor: it has already
seen the answers it is scored against. Each baseline report says which
rows it was fitted on, how many, and which labels its fitted label space
covers, so a reader can check the floor against the held-out labels.

    --baseline majority   the most common TRAIN label per family
                          (ties: first in sorted order)
    --baseline random     uniform draw from the TRAIN label space,
                          seeded (default 7), one stream per family
    --baseline frequency  seeded draw from the TRAIN label distribution
    --baseline retrieval  TF-IDF nearest neighbour over the TRAIN rows
    --baseline first_published / majority_published
                          copy-the-publisher heuristics: they read the
                          task's own input, never a label

    python scripts/score_benchmark.py --predictions preds.jsonl
    python scripts/score_benchmark.py --baseline majority --out reports/baselines/baseline_majority.json
    python scripts/score_benchmark.py --build-baselines   # all six reports
    python scripts/score_benchmark.py --check             # all six, drift
"""

from __future__ import annotations

import argparse
import collections
import json
import math
import os
import random
import re
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import benchmark_status as bstatus  # noqa: E402
import independent_benchmark_audit as audit  # noqa: E402

ROOT = _HERE.parent

SCORER_VERSION = "2"

#: The six published baseline reports, and how each is produced. The file
#: name is the contract: `--check` regenerates exactly these.
BASELINE_REPORTS = (
    ("baseline_majority.json", "majority", 7),
    ("baseline_random_seed7.json", "random", 7),
    ("baseline_frequency_seed7.json", "frequency", 7),
    ("baseline_first_published.json", "first_published", 7),
    ("baseline_majority_published.json", "majority_published", 7),
    ("baseline_retrieval.json", "retrieval", 7),
)

BASELINE_DIR = ROOT / "reports" / "baselines"
METRICS_JSON = ROOT / "reports" / "benchmark_metrics.json"
METRICS_MD = ROOT / "reports" / "benchmark_metrics.md"

WORD = re.compile(r"[a-z0-9]+")


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

def norm(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v).strip().lower()


def input_text(row: dict) -> str:
    return json.dumps(row.get("input"), sort_keys=True, ensure_ascii=False)


def tokenize(text: str) -> list[str]:
    return WORD.findall(text.lower())


def tfidf_vec(tokens: list[str], df: dict[str, int], n_docs: int
              ) -> dict[str, float]:
    tf: dict[str, int] = {}
    for t in tokens:
        tf[t] = tf.get(t, 0) + 1
    total = len(tokens) or 1
    return {t: (c / total) * math.log((1 + n_docs) / (1 + df.get(t, 0)))
            for t, c in tf.items()}


def cosine(a: dict[str, float], b: dict[str, float]) -> float:
    dot = sum(v * b.get(k, 0.0) for k, v in a.items())
    na = math.sqrt(sum(v * v for v in a.values()))
    nb = math.sqrt(sum(v * v for v in b.values()))
    return dot / (na * nb) if na and nb else 0.0


def macro_f1(pairs: list[tuple[str, str]]) -> float | None:
    """Unweighted mean F1 over the classes present in gold or prediction."""
    if not pairs:
        return None
    gold = [g for g, _ in pairs]
    pred = [p for _, p in pairs]
    labels = sorted(set(gold) | set(pred))
    scores = []
    for lab in labels:
        tp = sum(1 for g, p in zip(gold, pred) if g == lab and p == lab)
        fp = sum(1 for g, p in zip(gold, pred) if g != lab and p == lab)
        fn = sum(1 for g, p in zip(gold, pred) if g == lab and p != lab)
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        scores.append(2 * prec * rec / (prec + rec) if prec + rec else 0.0)
    return sum(scores) / len(scores)


def per_class_metrics(pairs: list[tuple[str, str]]) -> dict:
    """Precision / recall / F1 / support per label."""
    labels = sorted({g for g, _ in pairs} | {p for _, p in pairs})
    out = {}
    for lab in labels:
        tp = sum(1 for g, p in pairs if g == lab and p == lab)
        fp = sum(1 for g, p in pairs if g != lab and p == lab)
        fn = sum(1 for g, p in pairs if g == lab and p != lab)
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        out[lab] = {
            "precision": prec,
            "recall": rec,
            "f1": 2 * prec * rec / (prec + rec) if prec + rec else 0.0,
            "support": sum(1 for g, _ in pairs if g == lab),
        }
    return out


def summarise(pairs: list[tuple[str, str | None]],
              evaluable: bool = True) -> dict:
    """Counts and rates for a set of (gold, prediction) pairs.

    `evaluable=False` means the family cannot carry a meaningful accuracy
    (one observed label). The counts are still reported -- nothing is
    dropped -- but the rates are null and carry a reason.
    """
    n = len(pairs)
    answered = [(g, p) for g, p in pairs if p is not None]
    correct = sum(1 for g, p in answered if g == p)
    out: dict = {
        "scorable": n,
        "predicted": len(answered),
        "correct": correct,
    }
    if not evaluable:
        out["accuracy"] = None
        out["accuracy_scorable"] = None
        out["macro_f1"] = None
        out["accuracy_reason"] = "single_label_not_evaluable"
        return out
    out["accuracy"] = correct / len(answered) if answered else None
    out["accuracy_scorable"] = correct / n if n else None
    out["macro_f1"] = macro_f1(answered)
    out["accuracy_reason"] = None if answered else "no_predictions"
    return out


# ---------------------------------------------------------------------------
# family data
# ---------------------------------------------------------------------------

def load_families(status_rep: dict) -> dict[str, dict]:
    """Load every family's scorable rows.

    Only rows with a real scalar key are scorable: `answer_key_status ==
    "labeled"` and a non-empty projected label. The projection comes from
    the independent audit's registry, so the scorer and the audit score the
    same rows.
    """
    out: dict[str, dict] = {}
    for fname in sorted(audit.FAMILIES):
        path = bstatus.family_path(fname)
        if path is None or not path.is_file():
            continue
        rows_all = audit.load_family(fname)
        scorable = audit.scorable_rows(fname, rows_all)
        spec = audit.FAMILIES[fname]
        rows = []
        for r in scorable:
            rows.append({
                "tid": str(r.get("id") or r.get("task_id") or ""),
                "gold": audit.gold_of(r, spec["projection"]),
                "split": str(r.get("split", "unknown")),
                "text": input_text(r),
            })
        published: dict[str, list] = {}
        for r in scorable:
            pubs = (r.get("input") or {}).get("published_severities") or []
            if pubs:
                published[str(r.get("id") or r.get("task_id") or "")] = pubs
        out[fname] = {
            "rows": rows,
            "rows_total": len(rows_all),
            "rows_labeled": sum(1 for r in rows_all
                                if r.get("answer_key_status") == "labeled"),
            # the copy-the-publisher heuristics read the task's own input,
            # never a label
            "published_severities": published,
        }
    return out


def family_pairs(fam_rows: list[dict],
                 predictions: dict[str, str]) -> list[tuple[str, str | None]]:
    return [(r["gold"], norm(predictions[r["tid"]])
             if r["tid"] in predictions else None) for r in fam_rows]


# ---------------------------------------------------------------------------
# scoring core
# ---------------------------------------------------------------------------

def score_families(fam_data: dict[str, dict], predictions: dict[str, str],
                   status_rep: dict) -> dict:
    """Per-family statistics for every family that has scorable rows."""
    entries: dict[str, dict] = {}
    pairs_by_fam: dict[str, list] = {}
    for fname, data in sorted(fam_data.items()):
        status = status_rep["families"].get(fname)
        if status is None:
            continue
        pairs = family_pairs(data["rows"], predictions)
        pairs_by_fam[fname] = pairs
        evaluable = bool(status["evaluable"])
        entry = {"status": status["status"], "evaluable": evaluable,
                 # the accuracy below is over every scorable row of the
                 # family (train, validation and test together): a
                 # label-distribution diagnostic. The held-out result is
                 # the `test` entry of per_split.
                 "accuracy_scope": "all_scorable_rows"}
        entry.update(summarise(pairs, evaluable=evaluable))
        if not evaluable:
            entry["evaluable_reason"] = status.get("evaluable_reason")
        # per split
        by_split: dict[str, list] = collections.defaultdict(list)
        for (gold, pred), row in zip(pairs, data["rows"]):
            by_split[row["split"]].append((gold, pred))
        entry["per_split"] = {
            sp: summarise(ps, evaluable=evaluable)
            for sp, ps in sorted(by_split.items())}
        # per class
        answered = [(g, p) for g, p in pairs if p is not None]
        if evaluable:
            entry["per_class"] = per_class_metrics(answered)
        else:
            entry["per_class"] = {
                lab: {"precision": None, "recall": None, "f1": None,
                      "support": sum(1 for g, _ in answered if g == lab)}
                for lab in sorted({g for g, _ in answered})}
        entries[fname] = entry
    return {"entries": entries, "pairs": pairs_by_fam}


def micro_block(entries: dict[str, dict],
                pairs_by_fam: dict[str, list]) -> dict:
    """Aggregate a set of per-family entries into one micro block.

    The rates are computed over the EVALUABLE families only. A family whose
    scorable rows carry one label has no meaningful accuracy, so mixing it
    into a micro-average would publish its label distribution as predictive
    performance. Its rows are still counted in `scorable`/`predicted`/
    `correct`, and it is named in `non_evaluable_families`.
    """
    names = sorted(entries)
    total_s = sum(entries[f]["scorable"] for f in names)
    total_p = sum(entries[f]["predicted"] for f in names)
    total_c = sum(entries[f]["correct"] for f in names)
    ev = [f for f in names if entries[f]["evaluable"]]
    non_ev = [f for f in names if not entries[f]["evaluable"]]
    pairs = [p for f in ev for p in pairs_by_fam.get(f, [])]
    answered = [(g, p) for g, p in pairs if p is not None]
    block = {
        "scorable": total_s,
        "predicted": total_p,
        "correct": total_c,
        "evaluable_families": ev,
        "non_evaluable_families": non_ev,
    }
    if not ev:
        block.update({
            "accuracy": None, "accuracy_scorable": None, "macro_f1": None,
            "accuracy_denominator": 0, "accuracy_scorable_denominator": 0,
            "accuracy_reason": (
                "no evaluable family in this block: every contributing "
                "family has a single observed label "
                "(single_label_not_evaluable): " + ", ".join(non_ev)),
            "per_split": {}, "per_class": {},
        })
        return block
    acc = sum(1 for g, p in answered if g == p)
    block["accuracy"] = acc / len(answered) if answered else None
    block["accuracy_scorable"] = acc / len(pairs) if pairs else None
    block["macro_f1"] = macro_f1(answered)
    block["accuracy_denominator"] = len(answered)
    block["accuracy_scorable_denominator"] = len(pairs)
    block["accuracy_reason"] = (
        None if answered else
        "no_predictions: the evaluable families carry no prediction")
    # per_split is filled in by micro_with_splits, which knows the split of
    # every row; per_class is over the evaluable rows.
    block["per_split"] = {}
    block["per_class"] = per_class_metrics(answered)
    return block


def micro_with_splits(entries: dict[str, dict],
                      pairs_by_fam: dict[str, list],
                      split_by_fam: dict[str, list]) -> dict:
    """`micro_block` plus the per-split breakdown.

    The per-split rates are computed over the evaluable families only, the
    same rule as the block's own accuracy.
    """
    block = micro_block(entries, pairs_by_fam)
    ev = block["evaluable_families"]
    by_split: dict[str, list] = collections.defaultdict(list)
    for f in ev:
        for (gold, pred), sp in zip(pairs_by_fam.get(f, []),
                                    split_by_fam.get(f, [])):
            by_split[sp].append((gold, pred))
    block["per_split"] = {sp: summarise(ps) for sp, ps in sorted(by_split.items())}
    return block


# ---------------------------------------------------------------------------
# baselines: fitted on TRAIN ROWS ONLY
# ---------------------------------------------------------------------------

def _train_rows(rows: list[dict]) -> list[dict]:
    return [r for r in rows if r["split"] == "train"]


def _held_out(rows: list[dict]) -> list[dict]:
    return [r for r in rows if r["split"] != "train"]


def baseline_predictions(kind: str, fam_data: dict[str, dict],
                         seed: int = 7,
                         only: list[str] | None = None) -> tuple[dict[str, str], dict]:
    """Build a baseline's predictions and its fitting metadata.

    The returned metadata is the audit trail: for every family it records
    which rows the predictor was fitted on, how many, and which labels its
    fitted label space covers. A floor that was fitted on the held-out rows
    would show up here immediately.
    """
    preds: dict[str, str] = {}
    meta: dict[str, dict] = {}
    wanted = set(only) if only is not None else None
    for fname in sorted(fam_data):
        if wanted is not None and fname not in wanted:
            continue
        rows = fam_data[fname]["rows"]
        train = _train_rows(rows)
        tr_gold = [r["gold"] for r in train]
        space = sorted(set(tr_gold))
        test_gold = [r["gold"] for r in rows if r["split"] == "test"]
        val_gold = [r["gold"] for r in rows if r["split"] == "validation"]
        info = {
            "fitted_on": "train",
            "train_rows": len(train),
            "fitted_label_space": space,
            # the labels that occur only in the held-out split: a fitted
            # label space that contains one of them would mean the floor
            # saw the answer
            "test_only_labels": sorted(set(test_gold) - set(tr_gold)),
            "validation_only_labels": sorted(set(val_gold) - set(tr_gold)),
        }
        if not train:
            info["fit_note"] = ("no train rows: nothing to fit on, so the "
                                "predictor abstains")
        if kind in ("first_published", "majority_published"):
            # These read the task's own input. They fit nothing, so they
            # are not fitted on any label; saying so is the point.
            info["fitted_on"] = "input (no label is read)"
            info["train_rows"] = 0
            info["fitted_label_space"] = []
            published = fam_data[fname].get("published_severities") or {}
            for r in rows:
                pubs = published.get(r["tid"]) or []
                vals = [str(p.get("severity", "")).strip().lower()
                        for p in pubs if p.get("severity")]
                if not vals:
                    continue
                if kind == "first_published":
                    preds[r["tid"]] = vals[0]
                else:
                    top = collections.Counter(vals).most_common()
                    best = top[0][1]
                    preds[r["tid"]] = sorted(
                        g for g, n in top if n == best)[0]
            meta[fname] = info
            continue
        if kind == "retrieval":
            info["fit_note"] = "the index holds the train inputs only"
            preds.update(_retrieval_predictions(rows))
            meta[fname] = info
            continue
        if not train:
            meta[fname] = info
            continue
        # One RNG stream per family, seeded from the run seed and the
        # family name, so a family's numbers do not depend on which other
        # families happen to be in the run.
        rng = random.Random(f"{seed}:{fname}")
        if kind == "majority":
            top = collections.Counter(tr_gold).most_common()
            best_n = top[0][1]
            choice = sorted(g for g, n in top if n == best_n)[0]
            for r in rows:
                preds[r["tid"]] = choice
        elif kind == "random":
            for r in rows:
                preds[r["tid"]] = rng.choice(space)
        elif kind == "frequency":
            weights = [tr_gold.count(g) / len(tr_gold) for g in space]
            for r in rows:
                preds[r["tid"]] = rng.choices(space, weights=weights, k=1)[0]
        else:
            raise ValueError(f"unknown baseline {kind}")
        meta[fname] = info
    return preds, meta


def _retrieval_predictions(rows: list[dict]) -> dict[str, str]:
    """TF-IDF nearest-neighbour over the TRAIN rows of one family.

    The index holds train rows only: a held-out row's answer is never
    indexed, and a train row never retrieves itself.
    """
    train = _train_rows(rows)
    if not train:
        return {}
    toks = {r["tid"]: tokenize(r["text"]) for r in rows}
    df: dict[str, int] = collections.Counter()
    for r in train:
        for tok in set(toks[r["tid"]]):
            df[tok] = df.get(tok, 0) + 1
    vecs = {r["tid"]: tfidf_vec(toks[r["tid"]], df, len(train)) for r in rows}
    norm_of = {t: math.sqrt(sum(v * v for v in vec.values()))
               for t, vec in vecs.items()}
    # inverted index over the train rows, so a query only scores the train
    # rows that share a token with it
    index: dict[str, list[int]] = collections.defaultdict(list)
    for i, r in enumerate(train):
        for tok in set(toks[r["tid"]]):
            index[tok].append(i)
    out: dict[str, str] = {}
    train_pos = {r["tid"]: i for i, r in enumerate(train)}
    for r in rows:
        q = vecs[r["tid"]]
        nq = norm_of[r["tid"]]
        self_idx = train_pos.get(r["tid"])
        dots: dict[int, float] = collections.defaultdict(float)
        if nq:
            for tok, w in q.items():
                for i in index.get(tok, ()):
                    if i == self_idx:
                        # a train row never retrieves itself
                        continue
                    dots[i] += w * vecs[train[i]["tid"]].get(tok, 0.0)
        best_score = -1.0
        best = None
        for i, dot in sorted(dots.items()):
            nb = norm_of[train[i]["tid"]]
            score = dot / (nq * nb) if nb else 0.0
            if score > best_score:
                best_score = score
                best = i
        if best is None:
            # no shared token (or an empty query): every candidate scores
            # 0.0, and the first train row that is not the query wins
            best = 0
            if self_idx is not None and len(train) > 1 and self_idx == 0:
                best = 1
        out[r["tid"]] = train[best]["gold"]
    return out


# ---------------------------------------------------------------------------
# compatibility surface
#
# Other scripts and the existing unit tests import these names from this
# module. They are kept, and derived from the status module rather than
# hand-maintained, so there is still one source of truth.
# ---------------------------------------------------------------------------

def _projections() -> dict[str, tuple]:
    """family file -> (answer-key field, description).

    The field is None for a family whose answer is a scalar `answer`
    rather than a projected answer key. The registry is the independent
    audit's, so the scorer and the audit project the same field.
    """
    out: dict[str, tuple] = {}
    for fname, spec in sorted(audit.FAMILIES.items()):
        proj = spec["projection"]
        field = None if proj == "__answer__" else proj
        out[fname] = (field, spec.get("why", "scalar label"))
    return out


#: family file -> answer-key projection (None = not a projected key).
PROJECTIONS = _projections()


def key_dict(row: dict) -> dict:
    """The answer-key mapping of a row, whichever field carries it."""
    ak = row.get("answer_key")
    if isinstance(ak, dict):
        return ak
    a = row.get("answer")
    return a if isinstance(a, dict) else {"answer": a}


def load_tasks(include_retired: bool = False) -> dict:
    """{task_id: (family, gold, scorable)} for the scorable tasks.

    Without `include_retired` the tasks are the PRIMARY families' -- the
    set the headline metric covers. With it, every family ever shipped is
    returned, which is the scope of the continuity twin.
    """
    status_rep = bstatus.cached_status_report()
    fam_data = load_families(status_rep)
    wanted = None
    if not include_retired:
        wanted = set(status_rep["primary_families"])
    tasks: dict[str, tuple] = {}
    for fname, data in sorted(fam_data.items()):
        if wanted is not None and fname not in wanted:
            continue
        for r in data["rows"]:
            tasks[r["tid"]] = (fname, r["gold"], True)
    return tasks


def score_tasks(tasks: dict[tuple[str, str, bool]],
                predictions: dict[str, str],
                splits_of: dict[str, str]) -> dict:
    """Pure scoring core: {task_id: (family, gold, scorable)} + predictions
    + {task_id: split} -> per-family/micro report. Unit-tested with
    hand-computed fixtures; the audit-aware scorer uses score_families().
    """
    per_family: dict[str, dict] = collections.defaultdict(
        lambda: {"scorable": 0, "predicted": 0, "correct": 0,
                 "splits": collections.defaultdict(
                     lambda: {"scorable": 0, "predicted": 0, "correct": 0})})
    for tid, (fam, gold, scorable) in tasks.items():
        if not scorable:
            continue
        s = per_family[fam]
        sp = splits_of.get(tid, "unknown")
        s["scorable"] += 1
        s["splits"][sp]["scorable"] += 1
        if tid not in predictions:
            continue
        s["predicted"] += 1
        s["splits"][sp]["predicted"] += 1
        if norm(predictions[tid]) == gold:
            s["correct"] += 1
            s["splits"][sp]["correct"] += 1
    for fam, s in per_family.items():
        s["accuracy"] = (s["correct"] / s["predicted"]
                         if s["predicted"] else None)
        s["accuracy_scorable"] = (s["correct"] / s["scorable"]
                                  if s["scorable"] else None)
        s["splits"] = dict(sorted(s["splits"].items()))
        for ss in s["splits"].values():
            ss["accuracy"] = (ss["correct"] / ss["predicted"]
                              if ss["predicted"] else None)
    tot_s = sum(s["scorable"] for s in per_family.values())
    tot_p = sum(s["predicted"] for s in per_family.values())
    tot_c = sum(s["correct"] for s in per_family.values())
    return {
        "families": dict(sorted(per_family.items())),
        "micro": {"scorable": tot_s, "predicted": tot_p, "correct": tot_c,
                  "accuracy": tot_c / tot_p if tot_p else None,
                  "accuracy_scorable": tot_c / tot_s if tot_s else None},
    }


# ---------------------------------------------------------------------------
# report assembly
# ---------------------------------------------------------------------------

def build_report(predictions: dict[str, str], name: str,
                 fam_data: dict[str, dict], status_rep: dict,
                 baseline_meta: dict | None = None,
                 baseline_families: dict | None = None) -> dict:
    """Assemble the full report for one set of predictions."""
    scored = score_families(fam_data, predictions, status_rep)
    entries = scored["entries"]
    pairs = scored["pairs"]
    split_by_fam = {f: [r["split"] for r in fam_data[f]["rows"]]
                    for f in fam_data}

    status_of = status_rep["families"]
    primary_names = [f for f in sorted(entries)
                     if status_of.get(f, {}).get("status") == bstatus.STATUS_PRIMARY]
    exploratory = [f for f in sorted(entries)
                   if status_of.get(f, {}).get("status")
                   == bstatus.STATUS_EXPLORATORY and not status_of[f]["retired"]]
    invalid = [f for f in sorted(entries)
               if status_of.get(f, {}).get("status") == bstatus.STATUS_INVALID
               and not status_of[f]["retired"]]
    retired = [f for f in sorted(entries) if status_of[f]["retired"]]
    not_scorable = sorted(f for f, s in status_of.items()
                          if s["status"] == bstatus.STATUS_NOT_SCORABLE)
    unknown = sorted(f for f, s in status_of.items()
                     if s["status"] == bstatus.STATUS_UNKNOWN)

    def block(names: list[str]) -> dict:
        sub = {f: entries[f] for f in names}
        return {
            "families": sub,
            "micro": micro_with_splits(sub, pairs, split_by_fam),
        }

    primary = block(primary_names)
    expl = block(exploratory)
    inval = block(invalid)
    ret = block(retired)

    all_names = sorted(entries)
    all_block = {
        "families": {f: entries[f] for f in all_names},
        "micro": micro_with_splits({f: entries[f] for f in all_names},
                                   pairs, split_by_fam),
    }

    # coverage: the manifest's scorable total against what the scorer
    # actually covers, and how the rows are distributed over the statuses.
    manifest_scorable = _manifest_scorable_total()
    excluded_detail = {
        fam: {"reason": status_of[fam]["reason"],
              "tasks": _family_row_count(fam)}
        for fam in not_scorable}
    by_status = {}
    for st in bstatus.ALL_STATUSES:
        fams = [f for f in all_names
                if status_of.get(f, {}).get("status") == st]
        by_status[st] = {
            "families": fams,
            "scorable": sum(entries[f]["scorable"] for f in fams),
        }

    rep = {
        "run": name,
        "scorer_version": SCORER_VERSION,
        "scoring_rule": (
            "exact match on the lowercased projected scalar, labelled rows "
            "only; macro-F1 is unweighted over the classes present in gold "
            "or prediction"),
        "scope_note": (
            "the per-family and per-micro `accuracy` covers every scorable "
            "row of the block (train, validation and test together): it is a "
            "label-distribution diagnostic, not a held-out result. The "
            "held-out predictive performance is the `test` entry of "
            "`per_split`, and for a baseline the `baseline.heldout_test` "
            "block, which is fitted on train rows only"),
        "block_note": (
            "the four family blocks partition every scored family: "
            "`families` is the primary set the headline metric covers, "
            "`families_exploratory` and `families_invalid` are the demoted "
            "and the unusable ones, `families_retired` are the families that "
            "live under benchmark/retired_families/"),
        "status_rules": status_rep["rules"],
        "status_thresholds": status_rep["thresholds"],
        "family_status": {f: status_of[f] for f in sorted(status_of)},
        "primary_families": primary_names,
        "primary_denominator": primary["micro"]["scorable"],
        "families": primary["families"],
        "micro": primary["micro"],
        "families_exploratory": expl["families"],
        "micro_exploratory": expl["micro"],
        "families_invalid": inval["families"],
        "micro_invalid": inval["micro"],
        "families_retired": ret["families"],
        "micro_retired": ret["micro"],
        "micro_all_families": all_block["micro"],
        "not_scorable_families": {
            f: {"reason": status_of[f]["reason"]} for f in not_scorable},
        "unknown_families": {
            f: {"reason": status_of[f]["reason"]} for f in unknown},
        "coverage": {
            "manifest_scorable_total": manifest_scorable,
            # the headline covers the primary families' scorable rows; the
            # all-families scope is the continuity twin
            "scorer_covered": primary["micro"]["scorable"],
            "scorer_covered_primary": primary["micro"]["scorable"],
            "scored_rows_all_families": all_block["micro"]["scorable"],
            "by_status": by_status,
            "excluded_families": excluded_detail,
        },
        "excluded_families": {
            f: status_of[f]["reason"] for f in not_scorable},
    }
    if baseline_meta is not None:
        rep["baseline"] = baseline_meta
        for key in ("families", "families_exploratory", "families_invalid",
                    "families_retired"):
            rep[key] = _add_baseline_families(
                rep[key], baseline_families or {}, fam_data, predictions)
    return rep


def _add_baseline_families(entries: dict[str, dict], meta: dict[str, dict],
                           fam_data: dict[str, dict],
                           predictions: dict[str, str]) -> dict[str, dict]:
    """Attach the fitting metadata and the held-out results of the
    baseline to every family entry."""
    out = {}
    for fam, entry in entries.items():
        e = dict(entry)
        if fam in meta:
            info = dict(meta[fam])
            rows = fam_data[fam]["rows"]
            info["heldout_test"] = _heldout_metrics(
                rows, predictions, "test", entry.get("evaluable", True))
            info["heldout_validation"] = _heldout_metrics(
                rows, predictions, "validation", entry.get("evaluable", True))
            e["baseline"] = info
        out[fam] = e
    return out


def _heldout_metrics(rows: list[dict], predictions: dict[str, str],
                     split: str, evaluable: bool = True) -> dict:
    """Accuracy / macro-F1 / coverage of a prediction set on one split.

    A family whose scorable rows carry one observed label has no meaningful
    accuracy: the counts are reported, the rates are null with a reason.
    """
    sel = [r for r in rows if r["split"] == split]
    pairs = [(r["gold"], norm(predictions[r["tid"]]))
             for r in sel if r["tid"] in predictions]
    correct = sum(1 for g, p in pairs if g == p)
    out = {
        "rows": len(sel),
        "predicted": len(pairs),
        "correct": correct,
        "coverage": len(pairs) / len(sel) if sel else None,
    }
    if not evaluable:
        out["accuracy"] = None
        out["macro_f1"] = None
        out["accuracy_reason"] = "single_label_not_evaluable"
        return out
    out["accuracy"] = correct / len(pairs) if pairs else None
    out["macro_f1"] = macro_f1(pairs)
    out["accuracy_reason"] = None if pairs else "no_predictions"
    return out


def _family_row_count(family_file: str) -> int:
    """How many rows a family file holds (labelled or not)."""
    path = bstatus.family_path(family_file)
    if path is None or not path.is_file():
        return 0
    try:
        return sum(1 for line in path.read_text(encoding="utf-8").splitlines()
                   if line.strip())
    except OSError:
        return 0


def _manifest_scorable_total() -> int:
    total = 0
    try:
        m1 = json.loads((ROOT / "benchmark" / "manifest.json")
                        .read_text(encoding="utf-8-sig"))["tasks"]
        total += sum(v.get("scorable", 0) for v in m1.values()
                     if isinstance(v, dict))
    except (OSError, ValueError, KeyError):
        pass
    for mf in (ROOT / "benchmark" / "v3_manifest.json",
               ROOT / "Vbeta" / "benchmark_vbeta" / "vbeta_manifest.json"):
        try:
            mt = json.loads(mf.read_text(encoding="utf-8-sig"))["tasks"]
            total += sum(v if isinstance(v, int) else v.get("tasks", 0)
                         for v in mt.values())
        except (OSError, ValueError, KeyError):
            pass
    return total


# ---------------------------------------------------------------------------
# report rendering
# ---------------------------------------------------------------------------

def render_report(rep: dict) -> str:
    return json.dumps(rep, indent=2, sort_keys=True) + "\n"


def baseline_report(kind: str, seed: int, fam_data: dict[str, dict],
                    status_rep: dict) -> dict:
    """One baseline report: the full scorer report for that baseline."""
    preds, meta = baseline_predictions(kind, fam_data, seed=seed)
    name = f"baseline:{kind}:seed{seed}"
    baseline_meta = {
        "kind": kind,
        "seed": seed,
        "fitted_on": ("input (no label is read)"
                      if kind in ("first_published", "majority_published")
                      else "train"),
        "fitting_rule": _fitting_rule(kind),
        "note": (
            "every baseline that acts as a test floor is fitted on the TRAIN "
            "rows of its family and applied to the held-out rows; the "
            "per-family `baseline` block records the fitted rows, the "
            "fitted label space and the labels that occur only in the "
            "held-out split"),
    }
    rep = build_report(preds, name, fam_data, status_rep,
                       baseline_meta=baseline_meta,
                       baseline_families=meta)
    return rep


def _fitting_rule(kind: str) -> str:
    return {
        "majority": "the most common TRAIN label of the family "
                    "(ties: sorted-first)",
        "random": "uniform draw from the TRAIN label space, seeded with "
                  "seed and the family name",
        "frequency": "seeded draw from the TRAIN label distribution",
        "retrieval": "TF-IDF nearest neighbour over the TRAIN rows "
                     "(self excluded for train rows)",
        "first_published": "copy the first publisher's severity from the "
                           "task's own input (no label is read)",
        "majority_published": "copy the majority publisher severity from "
                              "the task's own input (no label is read)",
    }[kind]


# ---------------------------------------------------------------------------
# metric report (reports/benchmark_metrics.json / .md)
# ---------------------------------------------------------------------------

def _read_json(path: Path, default=None):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def _read_jsonl(path: Path) -> list[dict]:
    out: list[dict] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                out.append(json.loads(line))
    except (OSError, ValueError):
        pass
    return out


def _pct(n, d) -> str:
    return "not measurable" if not d else f"{n}/{d} ({100.0 * n / d:.1f}%)"


def _what_can_be_measured() -> tuple[list[list[str]], dict]:
    """The rows of the "what can be measured" table.

    A metric that needs a predictor is reported as not measurable rather
    than estimated. The numbers come from the reports that own them.
    """
    ver = _read_json(ROOT / "reports" / "verification_stats.json", {}) or {}
    patch = _read_json(ROOT / "reports" / "patch_verification.json", {}) or {}
    neg = _read_json(ROOT / "reports" / "negative_verification_stats.json",
                     {}) or {}
    negm = neg.get("metrics") or {}
    ce = _read_json(ROOT / "reports" / "counterexample_stats.json", {}) or {}
    leak = _read_json(ROOT / "reports" / "leakage_report.json", {}) or {}
    det = _read_jsonl(ROOT / "benchmark" / "A_vulnerability_detection.jsonl")
    fp = _read_jsonl(ROOT / "benchmark" / "F_false_positive_rejection.jsonl")
    ev = _read_jsonl(ROOT / "benchmark" / "retired_families"
                     / "E_exploit_verification.jsonl")
    d_t = _read_jsonl(ROOT / "benchmark" / "D_exploit_construction.jsonl")
    totals = ver.get("totals", {})
    comp = ver.get("poc_compilation_rate", {})
    ex_n = totals.get("exploit_records", 0)
    test_det = [t for t in det if t.get("split") == "test"]
    test_pos = sum(1 for t in test_det
                   if (t.get("answer_key") or {}).get("label") == "vulnerable")
    test_fp = [t for t in fp if t.get("split") == "test"
               and t.get("answer_key_status") == "labeled"]
    rows = [
        ["precision", "not measurable",
         "no model has been run against this benchmark; precision is a "
         "property of a predictor, not of the dataset. What the dataset "
         "provides is the labelled set needed to compute it."],
        ["recall", "not measurable", "same reason as precision."],
        ["F1", "not measurable", "same reason as precision."],
        ["false-positive rate", "not measurable",
         "requires a predictor. The benchmark supplies "
         f"{len(test_fp)} scorable false-positive-rejection tasks in the "
         "held-out split."],
        ["false-negative rate", "not measurable", "requires a predictor."],
        ["PoC compilation rate",
         _pct(comp.get("repos_compiled", 0), comp.get("repos_attempted", 0))
         + " repositories",
         f"{comp.get('poc_files_materialised', 0)} PoC files were written "
         f"from the code quoted in the reports; "
         f"{comp.get('poc_files_skipped', 0)} could not be expressed as a "
         "Solidity test body."],
        ["PoC execution rate",
         _pct(totals.get("reproduced", 0) + totals.get("not_reproduced", 0)
              + totals.get("inconclusive", 0), ex_n),
         "reproduced + not_reproduced + inconclusive over all exploit "
         "records."],
        ["exploit confirmation rate", _pct(totals.get("reproduced", 0), ex_n),
         "A PoC counts only when forge reported Success for that test. "
         "Nothing else is promoted."],
        ["patch verification rate",
         _pct(patch.get("evaluated", 0), patch.get("patch_records", 0)),
         f"{patch.get('fix_confirmed_effective', 0)} fixes confirmed "
         "effective by running the same PoC against vulnerable and fixed "
         "revisions."],
        ["negative-example accuracy", "not measurable",
         f"the held-out split has {len(test_fp)} scorable false-positive "
         f"tasks; of {neg.get('total', 0)} negatives only "
         f"{negm.get('reason_attributed_to_judge_or_sponsor', 0)} carry a "
         "reason attributed to a named judge or sponsor and "
         f"{negm.get('reason_supported_by_cited_code', 0)} are blocked by a "
         "gate in the cited code, while "
         f"{negm.get('unknown_or_insufficient_evidence', 0)} rest on a "
         "public label alone, so scoring them would reward guessing."],
        ["duplicate detection accuracy",
         f"{leak.get('near_duplicate_overlap', {}).get('count', 0)} "
         f"near-duplicate and "
         f"{leak.get('semantic_overlap', {}).get('count', 0)} semantic "
         "cross-split pairs found",
         "detector recall is not validated against a hand-labelled set; the "
         + ("pairs it found were checked by hand and are genuine."
            if leak.get("near_duplicate_overlap", {}).get("count")
            or leak.get("semantic_overlap", {}).get("count") else
            "no cross-split pair was found.")],
    ]
    totals_out = {
        "exploit_records": ex_n,
        "not_executed": totals.get("not_executed", 0),
        "not_reproduced": totals.get("not_reproduced", 0),
        "inconclusive": totals.get("inconclusive", 0),
        "reproduced": totals.get("reproduced", 0),
        "poc_files": len(d_t),
        "poc_labelled_rows": sum(1 for t in ev
                                 if t.get("answer_key_status") == "labeled"),
        "poc_unlabelled_rows": sum(
            1 for t in ev if t.get("answer_key_status") != "labeled"),
        "counterexamples": ce.get(
            "records_with_at_least_one_counterexample", 0),
        "confirmed_high_medium": ce.get("confirmed_high_medium_records", 0),
        "test_vulnerable": test_pos,
    }
    return rows, totals_out


def build_metrics_report(status_rep: dict, fam_data: dict[str, dict]) -> dict:
    """The machine-readable metric report.

    It carries the audited family statuses, the primary metric's
    denominator, the train-only baseline floors and the claims that were
    retracted -- so a reader cannot read a stale headline out of it.
    """
    man = {}
    try:
        man = json.loads((ROOT / "benchmark" / "manifest.json")
                         .read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        man = {}
    tasks = man.get("tasks", {}) or {}

    status_of = status_rep["families"]
    coverage = {}
    for name, t in sorted(tasks.items()):
        fam = name + ".jsonl"
        st = status_of.get(fam)
        entry = dict(t)
        if st:
            entry["status"] = st["status"]
            entry["status_reason"] = st["reason"]
            entry["evaluable"] = st["evaluable"]
            entry["evaluable_reason"] = st.get("evaluable_reason")
            entry["retired"] = st["retired"]
            entry["validity_flags"] = st["validity_flags"]
        coverage[name] = entry
    # families that live in their own manifests (R, S, T, U, V)
    for fam, data in sorted(fam_data.items()):
        name = fam[:-len(".jsonl")]
        if name in coverage:
            continue
        st = status_of.get(fam, {})
        by_split = collections.Counter(r["split"] for r in data["rows"])
        coverage[name] = {
            "file": st.get("path"),
            "tasks": data["rows_total"],
            "scorable": len(data["rows"]),
            "labeled": data["rows_labeled"],
            "partial": 0,
            "unlabeled": data["rows_total"] - data["rows_labeled"],
            "unscorable": data["rows_total"] - data["rows_labeled"],
            "by_split": dict(sorted(by_split.items())),
            "status": st.get("status"),
            "status_reason": st.get("reason"),
            "evaluable": st.get("evaluable"),
            "evaluable_reason": st.get("evaluable_reason"),
            "retired": st.get("retired"),
            "validity_flags": st.get("validity_flags", []),
        }

    # the primary metric: its denominator, its splits, its classes
    primary = status_rep["primary_families"]
    prim_rows = []
    for fam in primary:
        prim_rows.extend(fam_data[fam]["rows"])
    split_counts = collections.Counter(r["split"] for r in prim_rows)
    label_counts = collections.Counter(r["gold"] for r in prim_rows)

    floors = {}
    for _fn, kind, seed in BASELINE_REPORTS:
        preds, meta = baseline_predictions(kind, fam_data, seed=seed,
                                           only=primary)
        entry = {"kind": kind, "seed": seed, "fitted_on": "train"}
        per_fam = {}
        for fam in primary:
            rows = fam_data[fam]["rows"]
            test = [r for r in rows if r["split"] == "test"]
            correct = sum(1 for r in test
                          if r["tid"] in preds and norm(preds[r["tid"]])
                          == r["gold"])
            answered = sum(1 for r in test if r["tid"] in preds)
            pairs = [(r["gold"], norm(preds[r["tid"]]))
                     for r in test if r["tid"] in preds]
            per_fam[fam] = {
                "fitted_on": meta[fam]["fitted_on"],
                "train_rows": meta[fam]["train_rows"],
                "fitted_label_space": meta[fam]["fitted_label_space"],
                "test_rows": len(test),
                "test_predicted": answered,
                "test_correct": correct,
                "test_accuracy": correct / answered if answered else None,
                "test_macro_f1": macro_f1(pairs),
                "test_coverage": answered / len(test) if test else None,
                "test_only_labels": meta[fam]["test_only_labels"],
            }
        entry["primary"] = per_fam
        floors[kind] = entry

    # per-family held-out floors of the train-only majority baseline
    maj_preds, maj_meta = baseline_predictions("majority", fam_data, seed=7)
    family_floors = {}
    for fam in sorted(status_of):
        st = status_of[fam]
        if fam not in fam_data:
            continue
        rows = fam_data[fam]["rows"]
        test = [r for r in rows if r["split"] == "test"]
        answered = sum(1 for r in test if r["tid"] in maj_preds)
        correct = sum(1 for r in test
                      if r["tid"] in maj_preds
                      and norm(maj_preds[r["tid"]]) == r["gold"])
        entry = {
            "status": st["status"],
            "evaluable": st["evaluable"],
            "rows_scorable": st["rows_scorable"],
            "n_labels": st["n_labels"],
            "label_distribution": st["label_distribution"],
            "majority_fraction": st["majority_fraction"],
            "train_rows": maj_meta.get(fam, {}).get("train_rows", 0),
            "test_rows": len(test),
            "train_only_majority_floor_on_test": (
                correct / answered if answered else None),
            "test_only_labels": maj_meta.get(fam, {}).get(
                "test_only_labels", []),
            "shortcut_floor": st["shortcut_floor"],
        }
        if not st["evaluable"]:
            # One observed label: the "floor" would be the label
            # distribution, not predictive performance, so it is not
            # published as an accuracy. The row counts and the label
            # distribution stay.
            entry["train_only_majority_floor_on_test"] = None
            entry["accuracy"] = None
            entry["accuracy_reason"] = st.get("evaluable_reason")
            entry["floor_reason"] = (
                "single_label_not_evaluable: every scorable row carries one "
                "label, so the floor would restate the label distribution")
        family_floors[fam] = entry

    wcm_rows, wcm_totals = _what_can_be_measured()
    test_labels = collections.Counter(
        r["gold"] for fam in primary for r in fam_data[fam]["rows"]
        if r["split"] == "test")
    known_limitations = [
        f"Task D supplies {wcm_totals['poc_files']} PoC bodies quoted from "
        "reports. Their correctness is not established: only the fraction "
        "counted under *exploit confirmation rate* has been run.",
        f"Task E is labelled on its {wcm_totals['poc_labelled_rows']} rows "
        f"with an executed verdict; the other "
        f"{wcm_totals['poc_unlabelled_rows']} are unlabelled -- a PoC "
        "verification task needs an executed ground truth, and executing "
        "them needs an archive RPC and a working toolchain.",
        f"Task G is labelled on its "
        f"{status_of['G_patch_verification.jsonl']['rows_scorable']} rows "
        "where the same exploit was run against both the vulnerable and the "
        f"fixed revision (L6); the other "
        f"{coverage.get('G_patch_verification', {}).get('unlabeled', 0)} are "
        "`not_testable` -- no executable PoC on either side, so their "
        "effectiveness is genuinely unestablished.",
        f"Counterexamples exist for only "
        f"{wcm_totals['counterexamples']} of "
        f"{wcm_totals['confirmed_high_medium']} confirmed High/Medium "
        "findings. The reasons are counted in "
        "`reports/counterexample_stats.json`, not glossed over.",
        "Baseline predictors have been run (`reports/baselines/`, rubric in "
        "`docs/RUBRIC.md`): majority, label-frequency, copy-the-publisher, "
        "TF-IDF retrieval and seeded random. Every one of them is fitted on "
        "the train rows of its family and applied to the held-out rows; the "
        "rows each was fitted on are named in the report, so a floor fitted "
        "on the held-out rows would be visible rather than believed.",
        "A family whose scorable rows carry one observed label is not "
        "evaluable for accuracy: its accuracy is null with the reason "
        "`single_label_not_evaluable`, in every table, and a model beating "
        "it would mean nothing.",
    ]

    return {
        "generated_by": "scripts/score_benchmark.py --build-metrics",
        "note": ("family status, denominators and baseline floors are "
                 "computed by scripts/benchmark_status.py and "
                 "scripts/score_benchmark.py; metrics that need a predictor "
                 "are reported as not measurable rather than estimated"),
        "status_thresholds": status_rep["thresholds"],
        "status_rules": status_rep["rules"],
        "family_status": {
            fam: {
                "status": s["status"],
                "reason": s["reason"],
                "retired": s["retired"],
                "evaluable": s["evaluable"],
                "evaluable_reason": s.get("evaluable_reason"),
                "validity_flags": s["validity_flags"],
                "rows_scorable": s["rows_scorable"],
                "n_labels": s["n_labels"],
            }
            for fam, s in sorted(status_of.items())
        },
        "primary_metric": {
            "families": primary,
            "denominator": len(prim_rows),
            "scorable_rows": len(prim_rows),
            "by_split": dict(sorted(split_counts.items())),
            "label_distribution": dict(sorted(label_counts.items())),
            "test_label_distribution": dict(sorted(test_labels.items())),
            "test_rows": sum(test_labels.values()),
            "accuracy": None,
            "accuracy_reason": "not measurable: no predictor has been run "
                               "against this benchmark",
            "macro_f1": None,
            "macro_f1_reason": "not measurable: no predictor has been run "
                               "against this benchmark",
        },
        "baselines": floors,
        "family_floors": family_floors,
        "task_coverage": coverage,
        "what_can_be_measured": wcm_rows,
        "verification_totals": wcm_totals,
        "known_limitations": known_limitations,
        "retracted_claims": retracted_claims(status_rep, fam_data),
    }


def _pre_remediation_scope(status_rep: dict,
                            fam_data: dict[str, dict]) -> tuple[list[str], int]:
    """The scope the pre-remediation headline covered, recomputed.

    Before the audit-driven statuses existed, the headline was every
    non-retired family with at least the 100-row floor -- the scope the
    hand-written exploratory list produced on this data. Recomputing it
    keeps the retraction honest without typing the old row count.
    """
    names = [f for f, s in sorted(status_rep["families"].items())
             if not s["retired"]
             and s["status"] != bstatus.STATUS_NOT_SCORABLE
             and s["rows_scorable"] >= bstatus.THRESHOLDS["min_primary_rows"]]
    rows = sum(len(fam_data[f]["rows"]) for f in names if f in fam_data)
    return names, rows


def retracted_claims(status_rep: dict, fam_data: dict[str, dict]) -> list:
    """The published claims this change withdraws, with the reason."""
    status_of = status_rep["families"]
    old_names, old_rows = _pre_remediation_scope(status_rep, fam_data)
    primary_rows = sum(len(fam_data[f]["rows"]) for f in
                       status_rep["primary_families"])
    out = [
        {
            "claim": f"the headline micro-average covers {old_rows:,} "
                     f"scorable rows across {len(old_names)} families",
            "status": "RETRACTED",
            "replacement": (
                f"the headline micro-average covers {primary_rows} scorable "
                f"rows across "
                f"{len(status_rep['primary_families'])} family "
                f"({', '.join(status_rep['primary_families'])})"),
            "reason": (
                "the old headline set was decided by a hand-written "
                "retirement list, not by evidence: it included families the "
                "independent audit flags for split drift, saturation, "
                "record overlap and shortcut domination"),
        },
        {
            "claim": "families F, G, I and J score 1.000 (majority "
                     "accuracy 1.000 in the coverage table)",
            "status": "DOWNGRADED",
            "replacement": "accuracy is null with the reason "
                           "'single_label_not_evaluable'; their row counts "
                           "and label distributions are kept",
            "reason": ("every scorable row of those families carries one "
                       "label, so the published 1.000 was the label "
                       "distribution, not predictive performance"),
        },
        {
            "claim": "the published majority baseline is a test-set floor",
            "status": "RETRACTED",
            "replacement": "the baselines are fitted on train rows only and "
                           "applied to the held-out rows; the floors are "
                           "reported per family with the rows they were "
                           "fitted on",
            "reason": ("the old baselines were fitted over every labelled "
                       "row of a family, held-out rows included, so the "
                       "predictor had already seen the answers it was "
                       "scored against"),
        },
        {
            "claim": "a family is in the headline because its name is not on "
                     "a retirement list",
            "status": "RETRACTED",
            "replacement": "the status of every family is computed at run "
                           "time from the independent audit's own "
                           "measurements; an uncovered family file defaults "
                           "to UNKNOWN and is never primary",
            "reason": "a hard-coded list cannot justify an evaluation claim",
        },
    ]
    for fam in sorted(status_of):
        s = status_of[fam]
        if s["status"] == bstatus.STATUS_INVALID and s["validity_flags"]:
            out.append({
                "claim": f"{fam} is usable as evaluation evidence",
                "status": "RETRACTED",
                "replacement": f"status {s['status']}: {s['reason']}",
                "reason": "validity flags measured by the independent audit",
            })
    return out


def render_metrics_md(rep: dict) -> str:
    """The human-readable metric report."""
    lines = [
        "# Benchmark metrics",
        "",
        "Generated by `scripts/score_benchmark.py --build-metrics` from the",
        "audited family status (`scripts/benchmark_status.py`) and the",
        "committed benchmark files. Nothing in this file is estimated.",
        "",
        "## What can be measured",
        "",
        "| metric | value | basis |",
        "|---|---|---|",
    ]
    for name, value, basis in rep["what_can_be_measured"]:
        lines.append(f"| {name} | {value} | {basis} |")
    lines += [
        "",
        "## Which families count, and why",
        "",
        "A family enters the headline metric only when the independent audit",
        "finds no validity flag in it. The status is computed at run time from",
        "the data; no family is in the headline because its name is absent",
        "from a list. A family file that no rule covers defaults to",
        "UNKNOWN, which is never primary.",
        "",
        "| family | status | scorable | labels | train-only floor on test | why |",
        "|---|---|---|---|---|---|",
    ]
    for fam, s in sorted(rep["family_status"].items()):
        fl = rep["family_floors"].get(fam, {})
        floor = fl.get("train_only_majority_floor_on_test")
        floor_s = f"{floor:.4f}" if isinstance(floor, float) else "n/a"
        if s["status"] == "NOT_SCORABLE":
            floor_s = "n/a (not scorable)"
        elif not s["evaluable"]:
            floor_s = "n/a (one label: not evaluable)"
        lines.append(
            f"| `{fam}` | {s['status']} | {s['rows_scorable']} | "
            f"{s['n_labels']} | {floor_s} | {s['reason']} |")
    pm = rep["primary_metric"]
    lines += [
        "",
        "## Primary metric",
        "",
        f"- families: {', '.join(pm['families'])}",
        f"- denominator: {pm['denominator']} scorable rows",
        "- by split: " + ", ".join(f"{k}={v}" for k, v in
                                   pm["by_split"].items()),
        "- label distribution: " + ", ".join(
            f"{k}={v}" for k, v in pm["label_distribution"].items()),
        f"- accuracy: {pm['accuracy_reason']}",
        f"- macro-F1: {pm['macro_f1_reason']}",
        "",
        "## Baselines (fitted on train rows only)",
        "",
        "Every floor below is fitted on the family's train rows and applied",
        "to the held-out rows. The rows a floor was fitted on are named, so a",
        "floor fitted on the held-out rows would be visible rather than",
        "believed.",
        "",
        "| baseline | family | fitted on | train rows | test rows | accuracy |"
        " macro-F1 | coverage |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for kind, entry in sorted(rep["baselines"].items()):
        for fam, f in sorted(entry["primary"].items()):
            acc = f["test_accuracy"]
            lines.append(
                f"| {kind} | `{fam}` | {f['fitted_on']} | "
                f"{f['train_rows']} | {f['test_rows']} | "
                f"{('%.4f' % acc) if acc is not None else 'n/a'} | "
                f"{('%.4f' % f['test_macro_f1']) if f['test_macro_f1'] is not None else 'n/a'} | "
                f"{('%.4f' % f['test_coverage']) if f['test_coverage'] is not None else 'n/a'} |")
    lines += [
        "",
        "## Claims withdrawn by this change",
        "",
        "| claim | status | replacement | why |",
        "|---|---|---|---|",
    ]
    for c in rep["retracted_claims"]:
        lines.append(f"| {c['claim']} | {c['status']} | {c['replacement']} | "
                     f"{c['reason']} |")
    lines += [
        "",
        "## Task coverage",
        "",
        "A task is *scorable* only where an answer key genuinely exists.",
        "Unlabelled tasks are written to `benchmark/*.jsonl` with",
        "`answer_key_status` and a reason, and are excluded from any metric,",
        "because a key invented to fill a slot would measure the generator,",
        "not the model.",
        "",
        "| task | tasks | scorable | partial | unlabelled | train | validation"
        " | test | status |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for name, t in sorted(rep["task_coverage"].items()):
        bs = t.get("by_split", {})
        lines.append(
            f"| `{name}` | {t.get('tasks', 0)} | {t.get('scorable', 0)} | "
            f"{t.get('partial', 0)} | {t.get('unlabeled', 0)} | "
            f"{bs.get('train', 0)} | {bs.get('validation', 0)} | "
            f"{bs.get('test', 0)} | {t.get('status', 'n/a')} |")
    lines += [
        "",
        "## Held-out split composition (task A)",
        "",
    ]
    for label, n in sorted(pm.get("test_label_distribution", {}).items()):
        lines.append(f"- `{label}`: **{n}**")
    lines += [
        "",
        "A detector evaluated on this split is rewarded for saying",
        "`vulnerable` only when the Code4rena judge confirmed it, and",
        "penalised for flagging the rejected submissions. The train-only",
        "majority floor on this split is the number a model result must clear",
        "to mean anything; it is reported in the table above.",
        "",
        "## Known limitations of this benchmark",
        "",
    ]
    for item in rep["known_limitations"]:
        lines.append(f"- {item}")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _write(path: Path, text: str) -> None:
    """Write a report file.

    The write goes through a temporary file in the same directory and an
    atomic replace: a report that is half-written is worse than no report,
    and an in-place rewrite of a file another process may be reading is not
    always allowed.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"_{path.name}.tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    os.replace(tmp, path)


def _load_predictions(path: str) -> dict[str, str]:
    preds: dict[str, str] = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                r = json.loads(line)
                preds[r["task_id"]] = r.get("answer", "")
    return preds


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--predictions", default=None,
                    help="predictions JSONL: {task_id, answer}")
    ap.add_argument("--baseline",
                    choices=["majority", "random", "frequency",
                             "first_published", "majority_published",
                             "retrieval"], default=None)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", default=None, help="write JSON report here")
    ap.add_argument("--quiet", action="store_true",
                    help="machine mode: write only --out, print nothing")
    ap.add_argument("--build-baselines", action="store_true",
                    help="regenerate all six published baseline reports")
    ap.add_argument("--check", action="store_true",
                    help="fail if a published baseline report differs from a "
                         "regeneration")
    ap.add_argument("--build-metrics", action="store_true",
                    help="regenerate reports/benchmark_metrics.json and .md")
    ap.add_argument("--check-metrics", action="store_true",
                    help="fail if the metric reports differ from a "
                         "regeneration")
    args = ap.parse_args()

    if args.check or args.build_baselines or args.check_metrics \
            or args.build_metrics:
        return _rebuild_mode(args)

    if args.predictions:
        preds = _load_predictions(args.predictions)
        name = f"predictions:{args.predictions}"
        status_rep = bstatus.cached_status_report()
        fam_data = load_families(status_rep)
        rep = build_report(preds, name, fam_data, status_rep)
    elif args.baseline:
        status_rep = bstatus.cached_status_report()
        fam_data = load_families(status_rep)
        rep = baseline_report(args.baseline, args.seed, fam_data, status_rep)
    else:
        print("need --predictions or --baseline", file=sys.stderr)
        return 2

    emit = (lambda *a, **k: None) if args.quiet else print
    _print_summary(rep, emit)
    if args.out:
        out = Path(args.out)
        _write(out, render_report(rep))
        emit(f"wrote {out}")
    return 0


def _print_summary(rep: dict, emit) -> None:
    emit(f"{'family':42} {'status':13} {'scorable':>8} {'pred':>6} "
         f"{'correct':>7}  acc")
    for fam, s in rep["families"].items():
        acc = f"{s['accuracy']:.4f}" if s.get("accuracy") is not None else "n/a"
        emit(f"{fam:42} {s['status']:13} {s['scorable']:>8} "
             f"{s['predicted']:>6} {s['correct']:>7}  {acc}")
    m = rep["micro"]
    macc = f"{m['accuracy']:.4f}" if m.get("accuracy") is not None else "n/a"
    emit(f"{'MICRO (primary)':42} {'':13} {m['scorable']:>8} "
         f"{m['predicted']:>6} {m['correct']:>7}  {macc}")
    for sp, ss in (m.get("per_split") or {}).items():
        sacc = f"{ss['accuracy']:.4f}" if ss.get("accuracy") is not None \
            else "n/a"
        emit(f"  primary/{sp}: scorable={ss['scorable']} "
             f"predicted={ss['predicted']} correct={ss['correct']} "
             f"acc={sacc}")
    emit("primary families: " + ", ".join(rep["primary_families"]))
    emit(f"primary denominator: {rep['primary_denominator']}")
    for block, label in (("families_exploratory", "exploratory"),
                         ("families_invalid", "invalid"),
                         ("families_retired", "retired")):
        emit(f"{label}: " + (", ".join(rep[block]) or "-"))
    cov = rep.get("coverage", {})
    emit(f"coverage: primary={cov.get('scorer_covered_primary')} of manifest "
         f"scorable={cov.get('manifest_scorable_total')}; "
         f"all families={cov.get('scored_rows_all_families')}")


def _rebuild_mode(args) -> int:
    """--check / --build-baselines / --build-metrics / --check-metrics."""
    status_rep = bstatus.cached_status_report()
    fam_data = load_families(status_rep)
    rc = 0

    if args.check or args.build_baselines:
        for fname, kind, seed in BASELINE_REPORTS:
            rep = baseline_report(kind, seed, fam_data, status_rep)
            text = render_report(rep)
            path = BASELINE_DIR / fname
            if args.build_baselines:
                _write(path, text)
                print(f"wrote {path.relative_to(ROOT)}")
            else:
                if not path.is_file():
                    print(f"MISSING {path.relative_to(ROOT)}", file=sys.stderr)
                    rc = 1
                    continue
                cur = path.read_text(encoding="utf-8")
                if cur != text:
                    print(f"STALE {path.relative_to(ROOT)} -- regenerate with: "
                          f"python scripts/score_benchmark.py "
                          f"--build-baselines", file=sys.stderr)
                    rc = 1
                else:
                    print(f"current {path.relative_to(ROOT)}")
        if not args.build_baselines and rc == 0:
            print("all six baseline reports are current")

    if args.build_metrics or args.check_metrics:
        rep = build_metrics_report(status_rep, fam_data)
        jtext = json.dumps(rep, indent=2, sort_keys=True) + "\n"
        mtext = render_metrics_md(rep) + "\n"
        if args.build_metrics:
            _write(METRICS_JSON, jtext)
            _write(METRICS_MD, mtext)
            print(f"wrote {METRICS_JSON.relative_to(ROOT)}")
            print(f"wrote {METRICS_MD.relative_to(ROOT)}")
        else:
            for path, text in ((METRICS_JSON, jtext), (METRICS_MD, mtext)):
                if not path.is_file():
                    print(f"MISSING {path.relative_to(ROOT)}", file=sys.stderr)
                    rc = 1
                    continue
                if path.read_text(encoding="utf-8") != text:
                    print(f"STALE {path.relative_to(ROOT)} -- regenerate with: "
                          f"python scripts/score_benchmark.py "
                          f"--build-metrics", file=sys.stderr)
                    rc = 1
                else:
                    print(f"current {path.relative_to(ROOT)}")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
