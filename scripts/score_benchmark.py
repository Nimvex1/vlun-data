#!/usr/bin/env python3
"""Exact-match scorer for VLUN benchmark families.

Compares a predictions file against answer keys and reports per-family plus
micro-averaged accuracy. Writes nothing unless --out/--md is given.

Predictions file (JSONL, one row per task):
    {"task_id": "<family file id/task_id>", "answer": "<model answer>"}

Scoring rule (defined per family in RUBRIC.md, enforced here): the model's
answer, lowercased and stripped, must equal the projected scalar from the
answer key. Only tasks with answer_key_status == "labeled" are scored;
anything else is reported unscorable, never guessed. Families without an
exactly-scorable scalar (B: no labeled rows; D: generative; G: no labeled
rows; H: descriptive reference, no label; Q: judge-graded rubric) are
excluded with a stated reason — they need a judge, not string match.

Baselines (deterministic, reproducible):
    --baseline majority   predict the most common labeled answer per family
                          (ties: first in sorted order)
    --baseline random     predict uniformly from the family's observed answer
                          space with a fixed seed (default 7)

    python scripts/score_benchmark.py --predictions preds.jsonl
    python scripts/score_benchmark.py --baseline majority --out reports/baselines/baseline_majority.json
    python scripts/score_benchmark.py --baseline random --seed 7 --out reports/baselines/baseline_random.json
"""

from __future__ import annotations

import argparse
import collections
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# family file -> answer-key projection. None = not exactly scorable (reason).
PROJECTIONS = {
    "A_vulnerability_detection.jsonl": ("label", "scalar label"),
    "C_attacker_reasoning.jsonl": ("attacker_kind", "scalar label"),
    "E_exploit_verification.jsonl": ("verdict", "scalar label"),
    "F_false_positive_rejection.jsonl": ("label", "scalar label"),
    "I_verified_non_exploit.jsonl": ("label", "scalar label"),
    "J_verified_patch.jsonl": ("label", "scalar label"),
    "K_language_ecosystem_routing.jsonl": ("language", "scalar label"),
    "L_severity_reconciliation.jsonl": ("severity", "scalar label"),
    "M_experiment_level_classification.jsonl": ("level", "scalar label"),
    "N_attacker_identity_extraction.jsonl": ("actor_mentioned", "bool label"),
    "O_record_class_and_scope.jsonl": ("record_class", "scalar label"),
    "P_provenance_tier_and_rights.jsonl": ("highest_authority_tier",
                                           "scalar label"),
    "v3_R_source_tier_routing.jsonl": ("tier", "scalar label"),
    "v3_S_contest_outcome.jsonl": ("outcome", "scalar label"),
    "v3_T_taxonomy_explicit.jsonl": ("vulnerability_class",
                                     "scalar label"),
    "vbeta_U_language_routing.jsonl": (None, None),  # handled via answer
    "vbeta_V_source_tier_routing.jsonl": (None, None),
}

EXCLUDED = {
    "B_root_cause_reasoning.jsonl": "no labeled rows (partial/unlabeled only)",
    "D_exploit_construction.jsonl": "generative task: needs judge, not string match",
    "G_patch_verification.jsonl": "no labeled rows",
    "H_verified_exploit.jsonl": "descriptive reference, no label field",
    "Q_evidence_type_and_quality_rubric.jsonl": "judge-graded rubric dict",
}

FAMILY_DIRS = [ROOT / "benchmark", ROOT / "Vbeta" / "benchmark_vbeta"]


def norm(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v).strip().lower()


def input_text(row: dict) -> str:
    return json.dumps(row.get("input"), sort_keys=True, ensure_ascii=False)


def tfidf_vec(tokens: list[str], df: dict[str, int], n_docs: int
              ) -> dict[str, float]:
    import math
    tf: dict[str, int] = {}
    for t in tokens:
        tf[t] = tf.get(t, 0) + 1
    total = len(tokens) or 1
    return {t: (c / total) * math.log((1 + n_docs) / (1 + df.get(t, 0)))
            for t, c in tf.items()}


def tokenize(text: str) -> list[str]:
    import re
    return re.findall(r"[a-z0-9]+", text.lower())


def cosine(a: dict[str, float], b: dict[str, float]) -> float:
    import math
    dot = sum(v * b.get(k, 0.0) for k, v in a.items())
    na = math.sqrt(sum(v * v for v in a.values()))
    nb = math.sqrt(sum(v * v for v in b.values()))
    return dot / (na * nb) if na and nb else 0.0


def key_dict(row: dict) -> dict:
    ak = row.get("answer_key")
    if isinstance(ak, dict):
        return ak
    a = row.get("answer")
    return a if isinstance(a, dict) else {"answer": a}


def load_tasks():
    """Return {task_id: (family_file, gold_scalar or None, scorable)}."""
    tasks = {}
    for d in FAMILY_DIRS:
        if not d.is_dir():
            continue
        for path in sorted(d.glob("*.jsonl")):
            if "manifest" in path.name:
                continue
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    row = json.loads(line)
                    tid = row.get("id") or row.get("task_id")
                    labeled = row.get("answer_key_status") == "labeled"
                    if path.name in EXCLUDED or not labeled:
                        tasks[tid] = (path.name, None, False)
                        continue
                    proj = PROJECTIONS.get(path.name)
                    if proj is None:
                        tasks[tid] = (path.name, None, False)
                        continue
                    if proj[0] is None:
                        # vbeta families carry a scalar `answer` field.
                        gold = row.get("answer")
                    else:
                        gold = key_dict(row).get(proj[0])
                    tasks[tid] = (path.name, norm(gold), True)
    return tasks


def score_tasks(tasks: dict[str, tuple[str, str, bool]],
                predictions: dict[str, str],
                splits_of: dict[str, str]):
    """Pure scoring core: {task_id: (family, gold, scorable)} + predictions
    + {task_id: split} -> per-family/micro report. All file I/O lives in
    score(); this function is unit-tested with hand-computed fixtures."""
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


def score(predictions: dict[str, str]):
    tasks = load_tasks()
    splits_of: dict[str, str] = {}
    for d in FAMILY_DIRS:
        if not d.is_dir():
            continue
        for path in sorted(d.glob("*.jsonl")):
            if "manifest" in path.name:
                continue
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    row = json.loads(line)
                    tid = row.get("id") or row.get("task_id")
                    splits_of[tid] = str(row.get("split", "unknown"))
    rep = score_tasks(tasks, predictions, splits_of)
    per_family = rep["families"]
    # Manifest-scorable vs scorer-covered reconciliation. The manifest
    # counts every row with an answer key; the scorer covers the labeled
    # scalar-key subset (D generative, Q judge-graded, H descriptive
    # excluded with reasons in RUBRIC.md).
    manifest_scorable = 0
    try:
        m1 = json.load(open(ROOT / "benchmark" / "manifest.json",
                            encoding="utf-8-sig"))["tasks"]
        manifest_scorable += sum(
            v.get("scorable", 0) for v in m1.values()
            if isinstance(v, dict))
    except OSError:
        pass
    for mf in (ROOT / "benchmark" / "v3_manifest.json",
               ROOT / "Vbeta" / "benchmark_vbeta" / "vbeta_manifest.json"):
        try:
            mt = json.load(open(mf, encoding="utf-8-sig"))["tasks"]
            manifest_scorable += sum(
                v if isinstance(v, int)
                else v.get("tasks", 0) for v in mt.values())
        except OSError:
            pass
    tot_s = sum(s["scorable"] for s in per_family.values())
    tot_p = sum(s["predicted"] for s in per_family.values())
    tot_c = sum(s["correct"] for s in per_family.values())
    excluded_detail = {}
    for fam_file, reason in EXCLUDED.items():
        excluded_detail[fam_file] = {
            "reason": reason,
            "tasks": sum(1 for tid, (f, _, _) in tasks.items()
                         if f == fam_file)}
    return {
        "families": dict(sorted(per_family.items())),
        "micro": {"scorable": tot_s, "predicted": tot_p, "correct": tot_c,
                  "accuracy": tot_c / tot_p if tot_p else None,
                  "accuracy_scorable": tot_c / tot_s if tot_s else None},
        "coverage": {"manifest_scorable_total": manifest_scorable,
                     "scorer_covered": tot_s,
                     "excluded_families": excluded_detail},
        "excluded_families": EXCLUDED,
    }


def baseline_predictions(kind: str, seed: int = 7) -> dict[str, str]:
    tasks = load_tasks()
    by_fam: dict[str, list] = collections.defaultdict(list)
    ids: dict[str, list] = collections.defaultdict(list)
    for tid, (fam, gold, scorable) in tasks.items():
        if scorable:
            by_fam[fam].append(gold)
            ids[fam].append(tid)
    preds: dict[str, str] = {}
    rng = random.Random(seed)
    if kind == "frequency":
        # Label-frequency prior: seeded draw from the family's empirical
        # answer distribution (a stochastic constant predictor, distinct
        # from deterministic majority).
        for fam, golds in by_fam.items():
            dist = sorted(set(golds))
            weights = [golds.count(g) / len(golds) for g in dist]
            for tid in ids[fam]:
                preds[tid] = rng.choices(dist, weights=weights, k=1)[0]
        return preds
    if kind in ("first_published", "majority_published"):
        # Copy-the-publisher heuristics for L_severity_reconciliation:
        # predict from the task's own published_severities input. Only L
        # tasks get predictions; every other family reports zero coverage.
        for path in [ROOT / "benchmark"
                     / "L_severity_reconciliation.jsonl"]:
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    row = json.loads(line)
                    if row.get("answer_key_status") != "labeled":
                        continue
                    pubs = (row.get("input") or {}).get(
                        "published_severities") or []
                    vals = [str(p.get("severity", "")).strip().lower()
                            for p in pubs if p.get("severity")]
                    if not vals:
                        continue
                    tid = row.get("id") or row.get("task_id")
                    if kind == "first_published":
                        preds[tid] = vals[0]
                    else:
                        top = collections.Counter(vals).most_common()
                        best = top[0][1]
                        preds[tid] = sorted(
                            g for g, n in top if n == best)[0]
        return preds
    if kind == "retrieval":
        # TF-IDF nearest neighbour over task inputs. Index = train-split
        # tasks only (self excluded); every scorable task is predicted from
        # its nearest train neighbour's gold. Protocol documented in
        # docs/RUBRIC.md; leakage-free by construction (test answers never
        # indexed, and a train task never retrieves itself).
        return retrieval_predictions(seed)
    for fam, golds in by_fam.items():
        if kind == "majority":
            top = collections.Counter(golds).most_common()
            best_n = top[0][1]
            choice = sorted(g for g, n in top if n == best_n)[0]
        elif kind == "random":
            space = sorted(set(golds))
            for tid in ids[fam]:
                preds[tid] = rng.choice(space)
            continue
        else:
            raise ValueError(f"unknown baseline {kind}")
        for tid in ids[fam]:
            preds[tid] = choice
    return preds


def retrieval_predictions(seed: int = 7) -> dict[str, str]:
    tasks = load_tasks()
    rows: dict[str, tuple[str, str, str]] = {}  # tid -> (fam, gold, split)
    for d in FAMILY_DIRS:
        if not d.is_dir():
            continue
        for path in sorted(d.glob("*.jsonl")):
            if "manifest" in path.name or path.name in EXCLUDED:
                continue
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    row = json.loads(line)
                    if row.get("answer_key_status") != "labeled":
                        continue
                    tid = row.get("id") or row.get("task_id")
                    if tid in tasks and tasks[tid][2]:
                        rows[tid] = (path.name, tasks[tid][1],
                                     str(row.get("split", "unknown")))
    preds: dict[str, str] = {}
    fams: dict[str, list[str]] = collections.defaultdict(list)
    for tid, (fam, _, _) in rows.items():
        fams[fam].append(tid)
    for fam, tids in fams.items():
        train = [t for t in tids if rows[t][2] == "train"]
        if not train:
            continue
        toks = {t: tokenize(input_text(_row_of(t))) for t in tids}
        df: dict[str, int] = collections.Counter()
        for t in train:
            for tok in set(toks[t]):
                df[tok] = df.get(tok, 0) + 1
        vecs = {t: tfidf_vec(toks[t], df, len(train)) for t in tids}
        for t in tids:
            cands = [c for c in train if c != t] or train
            best = max(cands, key=lambda c: cosine(vecs[t], vecs[c]))
            preds[t] = rows[best][1]
    return preds


_row_cache: dict[str, dict] = {}


def _row_of(tid: str) -> dict:
    if tid not in _row_cache:
        for d in FAMILY_DIRS:
            if not d.is_dir():
                continue
            for path in sorted(d.glob("*.jsonl")):
                if "manifest" in path.name:
                    continue
                with open(path, encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        row = json.loads(line)
                        key = row.get("id") or row.get("task_id")
                        _row_cache[key] = row
    return _row_cache.get(tid, {})


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
    args = ap.parse_args()

    if args.predictions:
        preds = {}
        with open(args.predictions, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    r = json.loads(line)
                    preds[r["task_id"]] = r.get("answer", "")
        name = f"predictions:{args.predictions}"
    elif args.baseline:
        preds = baseline_predictions(args.baseline, args.seed)
        name = f"baseline:{args.baseline}:seed{args.seed}"
    else:
        print("need --predictions or --baseline", file=sys.stderr)
        return 2

    rep = score(preds)
    rep["run"] = name
    print(f"{'family':38} {'scorable':>8} {'pred':>6} {'correct':>7}  acc")
    for fam, s in rep["families"].items():
        acc = f"{s['accuracy']:.3f}" if s["accuracy"] is not None else "n/a"
        print(f"{fam:38} {s['scorable']:>8} {s['predicted']:>6} "
              f"{s['correct']:>7}  {acc}")
    m = rep["micro"]
    macc = f"{m['accuracy']:.4f}" if m["accuracy"] is not None else "n/a"
    print(f"{'MICRO':38} {m['scorable']:>8} {m['predicted']:>6} "
          f"{m['correct']:>7}  {macc}")
    a_fam = rep["families"].get("A_vulnerability_detection.jsonl")
    if a_fam:
        for sp, ss in a_fam["splits"].items():
            sacc = (f"{ss['accuracy']:.3f}" if ss["accuracy"] is not None
                    else "n/a")
            print(f"  A/{sp}: scorable={ss['scorable']} "
                  f"predicted={ss['predicted']} correct={ss['correct']} "
                  f"acc={sacc}")
    cov = rep.get("coverage", {})
    print(f"coverage: scorer={cov.get('scorer_covered')} of manifest "
          f"scorable={cov.get('manifest_scorable_total')}")
    print(f"excluded: {', '.join(sorted(rep['excluded_families']))}")
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(rep, fh, indent=2, sort_keys=True)
            fh.write("\n")
        print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
