#!/usr/bin/env python3
"""Independent benchmark-validity audit for VLUN families A-V.

Additive and read-only with respect to the dataset: this module NEVER
rewrites a benchmark row, an answer key, a split or a score. It reads the
committed benchmark files and emits a separate evaluation layer under
`benchmark/independent/` plus machine-readable results under
`reports/independent/`.

The distinction it exists to enforce: `scripts/score_benchmark.py` asks
"did the repo's own gates pass?"; this asks "does the benchmark measure
what it claims, or does a shortcut get the right answer?".

What it measures, per family:
  * answer-literal leakage -- the answer string appears in the
    model-facing `input`, so string search alone scores;
  * label degeneracy -- a single class, or a majority class above 0.95;
  * split-distribution drift -- train-majority applied to test, which is
    the floor an honest model must clear;
  * group overlap -- the same repository/record on both sides of the
    train/test boundary;
  * near-duplicate overlap -- 5-gram Jaccard to the nearest train task;
  * a class-disjoint secondary holdout where the family permits one.

Scoring note: "scoreable" here means an exactly-matchable scalar answer
key, the same subset `score_benchmark.py` scores. A family that is not
scalar (D generative, H descriptive, Q judge-graded) is reported with
`skipped_no_scorable_key`, never silently counted as zero.

Usage:
    python scripts/independent_benchmark_audit.py            # full audit
    python scripts/independent_benchmark_audit.py --check    # verify current
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Family registry. `projection` is the scalar the official scorer matches on
# (kept identical to scripts/score_benchmark.py PROJECTIONS so the two
# evaluations are comparable); `group` is the unit a group-disjoint split
# must hold out together.
# ---------------------------------------------------------------------------
FAMILIES: dict[str, dict] = {
    "A_vulnerability_detection.jsonl": {
        "dir": "benchmark", "projection": "label",
        "group": "record", "id": "id",
        "why": "detect a confirmed vulnerability from code",
    },
    "B_root_cause_reasoning.jsonl": {
        "dir": "benchmark/retired_families", "projection": "invariant_stated",
        "group": "record", "id": "id",
        "why": "does a source state a violated invariant",
    },
    "C_attacker_reasoning.jsonl": {
        "dir": "benchmark", "projection": "attacker_kind",
        "group": "record", "id": "id",
        "why": "classify the required attacker privilege",
    },
    "E_exploit_verification.jsonl": {
        "dir": "benchmark/retired_families", "projection": "verdict",
        "group": "record", "id": "id",
        "why": "verify an exploit actually executes",
    },
    "F_false_positive_rejection.jsonl": {
        "dir": "benchmark", "projection": "label",
        "group": "record", "id": "id",
        "why": "reject a false positive",
    },
    "G_patch_verification.jsonl": {
        "dir": "benchmark", "projection": "label",
        "group": "record", "id": "id",
        "why": "verify a patch is effective",
    },
    "I_verified_non_exploit.jsonl": {
        "dir": "benchmark", "projection": "label",
        "group": "record", "id": "id",
        "why": "verified non-exploit",
    },
    "J_verified_patch.jsonl": {
        "dir": "benchmark", "projection": "label",
        "group": "record", "id": "id",
        "why": "verified patch",
    },
    "K_language_ecosystem_routing.jsonl": {
        "dir": "benchmark/retired_families", "projection": "language",
        "group": "language", "id": "id",
        "why": "route a finding to its language and ecosystem",
    },
    "L_severity_reconciliation.jsonl": {
        "dir": "benchmark/retired_families", "projection": "severity",
        "group": "language", "id": "id",
        "why": "reconcile conflicting published severities",
    },
    "M_experiment_level_classification.jsonl": {
        "dir": "benchmark/retired_families", "projection": "level",
        "group": "record", "id": "id",
        "why": "classify the reproduction evidence level",
    },
    "N_attacker_identity_extraction.jsonl": {
        "dir": "benchmark/retired_families", "projection": "actor_mentioned",
        "group": "language", "id": "id",
        "why": "is a specific actor named",
    },
    "O_record_class_and_scope.jsonl": {
        "dir": "benchmark/retired_families", "projection": "record_class",
        "group": "language", "id": "id",
        "why": "classify the record's scope class",
    },
    "P_provenance_tier_and_rights.jsonl": {
        "dir": "benchmark/retired_families", "projection": "highest_authority_tier",
        "group": "language", "id": "id",
        "why": "apply tier rules and redistribution rights",
    },
    "v3_R_source_tier_routing.jsonl": {
        "dir": "benchmark", "projection": "tier",
        "group": "source", "id": "task_id",
        "why": "route a finding to a provenance tier",
    },
    "v3_S_contest_outcome.jsonl": {
        "dir": "benchmark/retired_families", "projection": "outcome",
        "group": "source", "id": "task_id",
        "why": "predict whether a contest entry was a finding",
    },
    "v3_T_taxonomy_explicit.jsonl": {
        "dir": "benchmark/retired_families", "projection": "vulnerability_class",
        "group": "source", "id": "task_id",
        "why": "predict the explicit auditor category",
    },
    "vbeta_U_language_routing.jsonl": {
        "dir": "Vbeta/benchmark_vbeta", "projection": "__answer__",
        "group": "source", "id": "task_id",
        "why": "route a finding to its language",
    },
    "vbeta_V_source_tier_routing.jsonl": {
        "dir": "Vbeta/benchmark_vbeta", "projection": "__answer__",
        "group": "source", "id": "task_id",
        "why": "route a finding to a provenance tier",
    },
}

# Families with no exactly-scorable scalar key: reported, never zero-filled.
def _pair_floor_text() -> str:
    """The published F-B floor, read from the baseline file, never hard-coded."""
    path = pathlib.Path(__file__).resolve().parent.parent / "reports" / "f_extension_baselines.json"
    try:
        floor = json.loads(path.read_text(encoding="utf-8"))["fb"]["reference_floor"]
    except (OSError, KeyError, ValueError):
        return "the published trivial-predictor floor"
    value = floor.get("micro_accuracy")
    if value is None:
        return "the published trivial-predictor floor"
    return f"{value:.4f} from the train-fitted trivial predictor"


PAIR_FLOOR_TEXT = _pair_floor_text()

NOT_SCORABLE = {
    "D_exploit_construction.jsonl":
        "generative task, needs a judge rather than string match",
    "H_verified_exploit.jsonl":
        "descriptive reference answers, no scalar label",
    "Q_evidence_type_and_quality_rubric.jsonl":
        "judge-graded rubric dict",
    # The F-extension families are shipped and registered, and they are scored - but
    # by their own per-axis / three-class scorer in scripts/score_f_extension.py, not
    # by the scalar exact-match projection that drives the headline micro-average.
    # Declaring them here keeps them out of the headline by rule and out of the
    # silence by name: they are reported as not scorable *by this scorer*, with the
    # reason, never scored 0 and read as a result.
    "Fa_rejection_evidence_axis_vector.jsonl":
        "not scorable by the headline exact-match projection: the gold is a vector of "
        "six axes plus per-axis assessability, so there is no single label to match. "
        "scripts/score_f_extension.py scores it per axis over the assessed axes only, "
        "and publishes the per-axis majority floor with it",
    "Fb_duplicate_radar_pair.jsonl":
        "not promoted into the headline: same_vulnerability / distinct_vulnerability / "
        "ambiguous is scalar in shape, but joining the micro-average would move the "
        f"published denominator while the pair floor is still {PAIR_FLOOR_TEXT}. "
        "scripts/score_f_extension.py scores it (with the published floors) "
        "and its row ids carry the split segment the shared row contract requires",
}

WORD = re.compile(r"[a-z0-9]+")

# Instruction scaffolding: restates the task and its label space, so the
# gold label appearing there is self-description, not leakage.
INSTRUCTION_KEYS = {"prompt", "class_vocabulary", "taxonomy",
                    "tier_rules", "prompt_to_answer"}
# Keys inside evidence blocks that literally contain the instruction text.
DROP_KEYS = {"prompt", "question", "instructions"}


def norm(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v).strip().lower()


def answer_key(row: dict) -> dict:
    ak = row.get("answer_key")
    if isinstance(ak, dict):
        return ak
    a = row.get("answer")
    return a if isinstance(a, dict) else {"answer": a}


def gold_of(row: dict, projection: str) -> str:
    if projection == "__answer__":
        a = row.get("answer")
        return norm(a.get("tier") if isinstance(a, dict)
                    and "tier" in a else a)
    return norm(answer_key(row).get(projection))


def input_text(row: dict) -> str:
    """Exactly the model-facing payload, flattened -- no id, no source."""
    parts: list[str] = []

    def walk(o):
        if isinstance(o, str):
            parts.append(o)
        elif isinstance(o, dict):
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(row.get("input"))
    return " ".join(parts)


def task_id(row: dict, idfield: str) -> str:
    return str(row.get(idfield) or "")


def group_key(row: dict, spec: dict) -> str:
    """The unit that must not straddle a group-disjoint split boundary."""
    src = row.get("source") or {}
    inp = row.get("input") or {}
    g = spec["group"]
    if g == "language":
        rid = src.get("record_id") or src.get("finding_id") or ""
        return rid.split(":")[0] or "unknown"
    if g == "source":
        # R/S/T carry a finding_id that identifies the contest entry; U/V
        # carry the publishing source, which is what the tier means.
        if isinstance(inp.get("source_id"), str):
            return inp["source_id"]
        rid = src.get("record_id") or src.get("finding_id") or ""
        return rid.split(":")[0] or "unknown"
    rid = src.get("record_id") or src.get("finding_id") or ""
    return rid or task_id(row, spec["id"])


def repo_of(row: dict) -> str:
    src = row.get("source") or {}
    rep = src.get("repository")
    if rep:
        return str(rep)
    rid = str(src.get("record_id") or src.get("finding_id") or "")
    for sep in ("/", ":"):
        if sep in rid:
            return rid.split(sep)[0]
    return rid


def code_blocks(row: dict) -> list:
    """Code blocks from a task input.

    `input.code` is a dict with `code_blocks` in families A-E, but a bare
    LIST of blocks in F, and absent elsewhere. Normalise here so every
    overlap check sees the same shape instead of guessing per family.
    """
    c = (row.get("input") or {}).get("code")
    if isinstance(c, dict):
        return c.get("code_blocks") or []
    if isinstance(c, list):
        return c
    return []


def shingles(text: str, k: int = 5) -> frozenset[str]:
    w = WORD.findall(text.lower())
    if len(w) < k:
        return frozenset([" ".join(w)])
    return frozenset(" ".join(w[i:i + k]) for i in range(len(w) - k + 1))


def load_family(fname: str) -> list[dict]:
    spec = FAMILIES[fname]
    path = ROOT / spec["dir"] / fname
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def scorable_rows(fname: str, rows: list[dict]) -> list[dict]:
    spec = FAMILIES[fname]
    return [r for r in rows
            if r.get("answer_key_status") == "labeled"
            and gold_of(r, spec["projection"]) not in ("", "none", "null")]


# ---------------------------------------------------------------------------
# Audit sections. Each returns a plain dict for the machine-readable report.
# ---------------------------------------------------------------------------

def _remove_key(value, drop: set, drop_all: bool) -> object:
    """Recursively drop instruction/label fields from a value.

    A prompt that ends "Answer vulnerable or no_confirmed_vulnerability"
    names the label space to every candidate, including the correct one.
    Counting that as leakage would make every family look compromised and
    hide the families where a real answer string sits in the *evidence*.
    """
    if isinstance(value, dict):
        return {k: _remove_key(v, drop, drop_all)
                for k, v in value.items() if k not in drop}
    if isinstance(value, list):
        return [_remove_key(v, drop, drop_all) for v in value]
    return value


def evidence_text(row: dict) -> str:
    """Model-facing evidence with the instruction scaffolding removed.

    Everything a model would read, minus the parts that only restate the
    task: the prompt, the label vocabulary, and the explicit prompt-to-
    answer field. What remains is the artifact the task is about.
    """
    inp = row.get("input")
    if isinstance(inp, dict):
        cleaned = {k: v for k, v in inp.items() if k not in INSTRUCTION_KEYS}
        inp = _remove_key(cleaned, DROP_KEYS, False)
        parts: list[str] = []

        def walk(o):
            if isinstance(o, str):
                parts.append(o)
            elif isinstance(o, dict):
                for v in o.values():
                    walk(v)
            elif isinstance(o, list):
                for v in o:
                    walk(v)

        walk(inp)
        return " ".join(parts)
    return input_text(row)


def audit_answer_leakage(fname: str, rows: list[dict]) -> dict:
    """Does the gold label appear in the model-facing EVIDENCE?

    Measured twice, because the distinction decides whether a family is
    compromised or merely self-describing:
      * in_evidence -- the label string occurs in the task's own artifact
        (prose, title, code), outside any instruction;
      * in_instruction -- it only occurs in the prompt / label
        vocabulary, which every task legitimately carries.
    Only `in_evidence` is real leakage.
    """
    spec = FAMILIES[fname]
    n = 0
    in_evidence = []
    in_instruction = []
    for r in rows:
        g = gold_of(r, spec["projection"])
        if not g or g in ("true", "false") or len(g) < 3:
            continue
        n += 1
        pat = r"(?<![a-z0-9])" + re.escape(g) + r"(?![a-z0-9])"
        if re.search(pat, evidence_text(r).lower()):
            in_evidence.append(task_id(r, spec["id"]))
        elif re.search(pat, input_text(r).lower()):
            in_instruction.append(task_id(r, spec["id"]))
    rate = len(in_evidence) / n if n else None
    return {
        "rows_checked": n,
        "answer_literal_in_evidence": len(in_evidence),
        "evidence_leak_rate": round(rate, 4) if rate is not None else None,
        "answer_only_in_instruction": len(in_instruction),
        "examples": in_evidence[:5],
        "verdict": ("answer_literal_leak" if rate and rate >= 0.5
                    else "weak_answer_echo" if in_evidence
                    else "clean"),
        "severity": ("high" if rate and rate >= 0.5
                     else "medium" if in_evidence else "none"),
    }


def audit_degeneracy(fname: str, rows: list[dict]) -> dict:
    """One class, or a majority so dominant the task cannot discriminate."""
    spec = FAMILIES[fname]
    golds = [gold_of(r, spec["projection"]) for r in rows]
    n = len(golds)
    if not n:
        return {"rows": 0, "verdict": "empty"}
    c = collections.Counter(golds)
    top, cnt = c.most_common(1)[0]
    frac = cnt / n
    if len(c) == 1:
        verdict = "single_label"
    elif n < 30:
        verdict = "too_small_to_score"
    elif frac >= 0.95:
        verdict = "saturated"
    elif frac >= 0.70:
        verdict = "near_degenerate"
    else:
        verdict = "usable"
    return {
        "rows": n, "n_labels": len(c),
        "majority_label": top, "majority_fraction": round(frac, 4),
        "label_distribution": dict(sorted(c.items())),
        "inv_gini": round(1 - sum((v / n) ** 2 for v in c.values()), 4),
        "verdict": verdict,
    }


def audit_split_drift(fname: str, rows: list[dict]) -> dict:
    """Train-majority applied to held-out rows: the honest shortcut floor."""
    spec = FAMILIES[fname]
    by_split = collections.defaultdict(list)
    for r in rows:
        by_split[str(r.get("split"))].append(gold_of(r, spec["projection"]))
    dist = {sp: dict(sorted(collections.Counter(g).items()))
            for sp, g in sorted(by_split.items())}
    tr = collections.Counter(by_split.get("train", []))
    te = by_split.get("test", [])
    drift = {}
    if tr and te:
        tr_major = tr.most_common(1)[0][0]
        correct = sum(1 for g in te if g == tr_major)
        drift = {
            "train_majority": tr_major,
            "test_rows": len(te),
            "train_majority_accuracy_on_test": round(correct / len(te), 4),
        }
    # Composition drift: how different is the held-out label mix? A test
    # split that is one class, or that shares no majority with train,
    # cannot be summarised by a single split-blind floor.
    if tr and te:
        tr_mix = {k: v / sum(tr.values()) for k, v in tr.items()}
        te_mix = {k: v / len(te) for k, v in collections.Counter(te).items()}
        keys = sorted(set(tr_mix) | set(te_mix))
        drift["label_mix_l1_distance"] = round(
            sum(abs(tr_mix.get(k, 0) - te_mix.get(k, 0)) for k in keys), 4)
        drift["test_labels_absent_from_train"] = sorted(
            set(te_mix) - set(tr_mix))
        drift["test_is_single_class"] = len(te_mix) == 1
    return {"per_split_label_distribution": dist, "train_majority_probe": drift}


def audit_group_overlap(fname: str, rows: list[dict]) -> dict:
    spec = FAMILIES[fname]
    tr = {group_key(r, spec) for r in rows if r.get("split") == "train"}
    te_rows = [r for r in rows if r.get("split") == "test"]
    shared = {group_key(r, spec) for r in te_rows} & tr
    return {
        "group_type": spec["group"],
        "train_groups": len(tr),
        "test_groups": len({group_key(r, spec) for r in te_rows}),
        "shared_groups": len(shared),
        "test_rows_in_shared_group": sum(
            1 for r in te_rows if group_key(r, spec) in tr),
        "test_rows": len(te_rows),
        "test_rows_in_shared_group_pct": round(
            100 * sum(1 for r in te_rows if group_key(r, spec) in tr) / len(te_rows), 2
        ) if te_rows else None,
    }


def audit_record_and_repo_overlap(fname: str, rows: list[dict]) -> dict:
    def rid(r):
        s = r.get("source") or {}
        return str(s.get("record_id") or s.get("finding_id") or "")

    tr_r = {rid(r) for r in rows if r.get("split") == "train"}
    te_r = {rid(r) for r in rows if r.get("split") == "test"}
    tr_repo = {repo_of(r) for r in rows if r.get("split") == "train"}
    te_rows = [r for r in rows if r.get("split") == "test"]
    tr_code = set()
    tr_files = set()
    for r in rows:
        if r.get("split") != "train":
            continue
        for b in code_blocks(r):
            if not isinstance(b, dict):
                continue
            if b.get("code"):
                tr_code.add(hashlib.sha1(
                    str(b["code"]).encode()).hexdigest())
            if b.get("file"):
                tr_files.add(b["file"])
    dup_code = 0
    dup_file = 0
    for r in te_rows:
        blocks = [b for b in code_blocks(r) if isinstance(b, dict)]
        if any(hashlib.sha1(str(b.get("code")).encode()).hexdigest()
               in tr_code for b in blocks if b.get("code")):
            dup_code += 1
        if any(b.get("file") in tr_files for b in blocks if b.get("file")):
            dup_file += 1
    return {
        "record_id_overlap": len(tr_r & te_r),
        "repositories_shared": len(tr_repo & {repo_of(r) for r in te_rows}),
        "test_rows_with_shared_repo": sum(
            1 for r in te_rows if repo_of(r) in tr_repo),
        "test_rows_with_identical_code_block": dup_code,
        "test_rows_with_shared_code_file_path": dup_file,
        "test_rows": len(te_rows),
    }


def audit_near_duplicates(fname: str, rows: list[dict],
                          sample: int = 400) -> dict:
    """Nearest train neighbour by 5-gram Jaccard, per held-out row."""
    spec = FAMILIES[fname]
    tr = [r for r in rows if r.get("split") == "train"]
    te = [r for r in rows if r.get("split") == "test"]
    if not tr or not te:
        return {"verdict": "skipped_no_scorable_key"}
    tr_sh = [shingles(input_text(r)) for r in tr]
    tr_idx = collections.defaultdict(list)
    for i, s in enumerate(tr_sh):
        for x in s:
            tr_idx[x].append(i)
    sims = []
    label_agree = 0
    for r in te[:sample]:
        s = shingles(input_text(r))
        if not s or s == frozenset({""}):
            continue
        cand = collections.Counter()
        for x in s:
            for j in tr_idx.get(x, ()):
                cand[j] += 1
        best = 0.0
        best_j = None
        for j in cand:
            B = tr_sh[j]
            inter = len(s & B)
            jac = inter / (len(s) + len(B) - inter) if (s or B) else 0.0
            if jac > best:
                best, best_j = jac, j
        if best_j is None:
            continue
        sims.append(best)
        if best >= 0.9 and gold_of(r, spec["projection"]) == gold_of(
                tr[best_j], spec["projection"]):
            label_agree += 1
    hi = sum(1 for x in sims if x >= 0.9)
    ordered = sorted(sims)
    return {
        "test_rows_sampled": len(sims),
        "nearest_train_similarity_max": round(max(sims), 4) if sims else None,
        "nearest_train_similarity_median": (
            round(ordered[len(ordered) // 2], 4) if ordered else None),
        "test_rows_sim_ge_0.9": hi,
        "of_those_label_matches_train": label_agree,
        "verdict": ("near_duplicate_leak" if hi and hi / max(len(sims), 1) >= 0.2
                    else "clean"),
    }


def macro_f1(gold: list[str], pred: list[str]) -> float | None:
    """Unweighted mean F1 across classes present in gold or pred."""
    if not gold:
        return None
    labels = sorted(set(gold) | set(pred))
    scores = []
    for lab in labels:
        tp = sum(1 for g, p in zip(gold, pred) if g == lab and p == lab)
        fp = sum(1 for g, p in zip(gold, pred) if g != lab and p == lab)
        fn = sum(1 for g, p in zip(gold, pred) if g == lab and p != lab)
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        scores.append(2 * prec * rec / (prec + rec) if prec + rec else 0.0)
    return round(sum(scores) / len(scores), 4)


def baselines(fname: str, rows: list[dict], seed: int = 7) -> dict:
    """Meaningless-baseline floor for one family.

    Every baseline is fitted on TRAIN ONLY and applied to the held-out
    rows, because a baseline fitted on the test set measures nothing.
    """
    import random

    spec = FAMILIES[fname]
    tr = [r for r in rows if r.get("split") == "train"]
    te = [r for r in rows if r.get("split") == "test"]
    if not tr or not te:
        return {"verdict": "skipped_no_holdout"}
    tr_gold = [gold_of(r, spec["projection"]) for r in tr]
    te_gold = [gold_of(r, spec["projection"]) for r in te]
    space = sorted(set(tr_gold))
    rng = random.Random(seed)
    out: dict = {"train_rows": len(tr), "test_rows": len(te),
                 "answer_space_from_train": len(space)}

    def report(name, preds):
        acc = sum(1 for g, p in zip(te_gold, preds) if g == p) / len(te_gold)
        out[name] = {
            "accuracy": round(acc, 4),
            "macro_f1": macro_f1(te_gold, preds),
            "coverage": round(len(preds) / len(te_gold), 4),
        }

    # majority-from-train
    maj = collections.Counter(tr_gold).most_common(1)[0][0]
    report("majority_from_train", [maj] * len(te_gold))
    # global majority over all labelled rows (what score_benchmark does)
    allg = [gold_of(r, spec["projection"]) for r in rows]
    gm = collections.Counter(allg).most_common(1)[0][0]
    report("majority_global_official", [gm] * len(te_gold))
    # uniform random from the train answer space
    report("random_from_train_space",
           [rng.choice(space) for _ in te_gold])
    # frequency: seeded draw from the train empirical distribution
    w = [tr_gold.count(g) / len(tr_gold) for g in space]
    report("frequency_from_train",
           [rng.choices(space, weights=w, k=1)[0] for _ in te_gold])
    def title_of(r):
        return str((r.get("input") or {}).get("title", ""))

    tr_tok = [set(WORD.findall(title_of(r).lower())) for r in tr]
    tr_any = [set(WORD.findall(input_text(r).lower())) for r in tr]
    for label, toks in (("title_retrieval", tr_tok),
                        ("input_retrieval", tr_any)):
        preds = []
        for r in te:
            q = set(WORD.findall(title_of(r).lower() if label
                                 == "title_retrieval"
                                 else input_text(r).lower()))
            best, best_j = -1.0, None
            for j, t in enumerate(toks):
                if not t or not q:
                    continue
                inter = len(q & t)
                jac = inter / (len(q) + len(t) - inter)
                if jac > best:
                    best, best_j = jac, j
            preds.append(gold_of(tr[best_j], spec["projection"])
                         if best_j is not None else maj)
        report(label, preds)
    # source-only: the group key alone (e.g. publisher -> tier)
    gmap = collections.defaultdict(collections.Counter)
    for r in tr:
        gmap[group_key(r, spec)][gold_of(r, spec["projection"])] += 1
    preds, cov = [], 0
    for r in te:
        g = group_key(r, spec)
        if g in gmap:
            cov += 1
            preds.append(gmap[g].most_common(1)[0][0])
        else:
            preds.append(maj)
    acc = sum(1 for g, p in zip(te_gold, preds) if g == p) / len(te_gold)
    out["source_only_lookup"] = {
        "accuracy": round(acc, 4), "macro_f1": macro_f1(te_gold, preds),
        "coverage": round(cov / len(te_gold), 4),
    }
    best_shortcut = max(
        (out[k]["accuracy"] for k in out
         if isinstance(out[k], dict) and "accuracy" in out[k]),
        default=None)
    out["best_shortcut_accuracy"] = best_shortcut
    return out


def class_disjoint_split(fname: str, rows: list[dict]) -> dict:
    """A holdout whose labels never appear in the retained train side.

    Only meaningful when the label space has >=2 classes with enough
    support; otherwise the task is degenerate and no honest split exists.
    """
    spec = FAMILIES[fname]
    c = collections.Counter(gold_of(r, spec["projection"]) for r in rows)
    if len(c) < 2:
        return {"verdict": "skipped_single_class",
                "reason": "task has one class; class-disjoint eval is vacuous"}
    rare = sorted(c.items(), key=lambda x: (x[1], x[0]))[0]
    if rare[1] < 5:
        return {"verdict": "skipped_insufficient_minority_support",
                "reason": f"rarest class {rare[0]!r} has n={rare[1]}",
                "label_counts": dict(sorted(c.items()))}
    # Hold out EVERY row of the two rarest classes; keep the rest as train.
    hold_labs = {lab for lab, _ in sorted(c.items(), key=lambda x: (x[1], x[0]))[:2]}
    held = [r for r in rows if gold_of(r, spec["projection"]) in hold_labs]
    kept = [r for r in rows if gold_of(r, spec["projection"]) not in hold_labs]
    # group-disjoint too: never split a group across the boundary
    held_groups = {group_key(r, spec) for r in held}
    kept = [r for r in kept if group_key(r, spec) not in held_groups]
    return {
        "verdict": "built",
        "held_out_labels": sorted(hold_labs),
        "held_out_rows": len(held),
        "kept_rows": len(kept),
        "group_disjoint": True,
        "kept_groups": len({group_key(r, spec) for r in kept}),
        "held_out_groups": len(held_groups),
        "label_counts": dict(sorted(c.items())),
    }


def run_audit(seed: int = 7) -> dict:
    families = {}
    # Families with no exactly-scorable key are listed first and always,
    # so a reader can see they were considered rather than forgotten.
    for fname, reason in sorted(NOT_SCORABLE.items()):
        path = None
        for d in (ROOT / "benchmark", ROOT / "Vbeta" / "benchmark_vbeta"):
            cand = d / fname
            if cand.is_file():
                path = cand
                break
        n = 0
        if path is not None:
            n = sum(1 for line in path.read_text(encoding="utf-8").splitlines()
                    if line.strip())
        families[fname] = {
            "verdict": "skipped_no_scorable_key",
            "reason": reason,
            "rows": n,
        }
    for fname, spec in sorted(FAMILIES.items()):
        rows_all = load_family(fname)
        if fname in NOT_SCORABLE:
            continue
        rows = scorable_rows(fname, rows_all)
        entry = {
            "claim": spec["why"],
            "rows_total": len(rows_all),
            "rows_scorable": len(rows),
            "rows_unlabeled": len(rows_all) - len(rows),
            "answer_leakage": audit_answer_leakage(fname, rows),
            "degeneracy": audit_degeneracy(fname, rows),
            "split_drift": audit_split_drift(fname, rows),
            "group_overlap": audit_group_overlap(fname, rows),
            "record_overlap": audit_record_and_repo_overlap(fname, rows),
            "near_duplicates": audit_near_duplicates(fname, rows),
            "baselines_test_split": baselines(fname, rows, seed),
            "class_disjoint": class_disjoint_split(fname, rows),
        }
        # Headline: can this family discriminate at all?
        flags = []
        if entry["degeneracy"]["verdict"] == "single_label":
            flags.append("single_label")
        if entry["degeneracy"]["verdict"] == "too_small_to_score":
            flags.append("too_small_to_score")
        if entry["degeneracy"]["verdict"] == "saturated":
            flags.append("saturated")
        if entry["answer_leakage"]["verdict"] == "answer_literal_leak":
            flags.append("answer_literal_leak")
        if entry["near_duplicates"]["verdict"] == "near_duplicate_leak":
            flags.append("near_duplicate_leak")
        if entry["group_overlap"]["shared_groups"]:
            flags.append("group_overlap")
        if entry["record_overlap"]["record_id_overlap"]:
            flags.append("record_id_overlap")
        if entry["record_overlap"]["test_rows_with_identical_code_block"]:
            flags.append("shared_code")
        probe = entry["split_drift"]["train_majority_probe"]
        if probe.get("test_labels_absent_from_train"):
            flags.append("held_out_labels_unseen_in_train")
        # A held-out side too small to estimate anything on.
        if probe.get("test_rows", 0) < 30:
            flags.append("holdout_too_small")
        # The held-out mix must resemble the retained mix, or a score says
        # more about the partition than the model.
        if (probe.get("label_mix_l1_distance") or 0) >= 0.40:
            flags.append("split_composition_drift")
        entry["validity_flags"] = flags
        entry["usable_as_evidence"] = not flags
        families[fname] = entry
    return {
        "audit_version": "1",
        "seed": seed,
        "scoring_rule": (
            "identical to scripts/score_benchmark.py: exact match on the "
            "lowercased projected scalar, labeled rows only; macro-F1 is "
            "unweighted over classes present in gold or prediction"),
        "families": families,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="reports/independent/audit.json")
    ap.add_argument("--check", action="store_true",
                    help="fail if the committed audit differs")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    rep = run_audit(args.seed)
    out = ROOT / args.out
    text = json.dumps(rep, indent=2, sort_keys=True) + "\n"
    if args.check:
        if not out.is_file():
            print(f"missing {out}", file=sys.stderr)
            return 1
        cur = out.read_text(encoding="utf-8")
        if cur != text:
            print(f"STALE {out} -- run: python "
                  f"scripts/independent_benchmark_audit.py", file=sys.stderr)
            return 1
        print("independent audit is current")
        return 0
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8", newline="\n")
    scored = {f: v for f, v in rep["families"].items()
              if "validity_flags" in v}
    skipped = [f for f, v in rep["families"].items()
               if v.get("verdict", "").startswith("skipped")]
    usable = [f for f, v in scored.items() if v["usable_as_evidence"]]
    print(f"wrote {out}")
    print(f"families audited: {len(scored)} scorable + {len(skipped)} "
          f"not scorable; usable as evidence: {len(usable)}")
    for f, v in sorted(scored.items()):
        flags = ",".join(v["validity_flags"]) or "clean"
        print(f"  {f:40} {flags}")
    for f in sorted(skipped):
        print(f"  {f:40} {rep['families'][f]['verdict']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())