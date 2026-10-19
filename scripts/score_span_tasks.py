#!/usr/bin/env python3
"""Score evidence-span tasks on FOUR INDEPENDENT axes + abstention (spec 10).

Axes (reported separately, never collapsed into one number):

  answer_correctness   predicted severity == held-out expected severity, over
                       submissions that attempted an answer.
  citation_existence   the submission produced a span object at all.
  citation_exactness   cited byte bounds are within the documented tolerance of
                       the expected span bounds (manifest tolerance_bytes=0).
  span_support         sha256 of the PINNED source bytes at the CITED bounds
                       equals the expected span hash -- verified against the
                       source, NOT against the model's own quote.
  abstention           correct abstain on unavailable spans; wrong abstain
                       (abstaining on a verifiable task) penalised.

Confusion emitted between "cited but unsupported" (a citation whose bytes do
not ground in the source) and "unsupported-but-cited" (fabricating a span on an
unavailable task that expects abstention).

The scorer reads ONLY derived_span_tasks/answer_key.jsonl (held-out) + the
pinned sources under V3/clones; it never reads the model-facing prompt for
ground truth. If no real model outputs exist in the repo (work/predict and
reports/baseline hold severity-classifier rows, not span citations), the
--baseline path runs the scorer over SELF-GENERATED MECHANICAL BASELINES
(exact / off-by-one / random-span / plausible-wrong / abstain). Those are
labelled mechanical baselines, NOT a real model result.

Writes:
    reports/span_scoring_report.json
    reports/span_scoring_report.md
    work/scoreval/baseline_submissions.jsonl   (only in --baseline mode)

Usage:
    python scripts/score_span_tasks.py
    python scripts/score_span_tasks.py --submissions path.jsonl
    python scripts/score_span_tasks.py --limit 400 --seed 20261018
    python scripts/score_span_tasks.py --check
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import vlun_v3 as V  # noqa: E402

AK = ROOT / "derived_span_tasks" / "answer_key.jsonl"
MANIFEST = ROOT / "derived_span_tasks" / "manifest.json"
REPORTS = ROOT / "reports"
BASELINE_OUT = ROOT / "work" / "scoreval" / "baseline_submissions.jsonl"
SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational", "Unknown"]
DEFAULT_SEED = 20261018
DEFAULT_LIMIT = 400


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def canon_json_text(obj) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _read_jsonl(path: Path) -> list[dict]:
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def _is_abstain(sub: dict) -> bool:
    if sub.get("abstain") is True:
        return True
    ans = sub.get("answer")
    span = sub.get("span")
    return (ans in (None, "", sub.get("abstain_token"))) and not span


def _span_bounds(span) -> tuple[int, int] | None:
    if not isinstance(span, dict):
        return None
    s, e = span.get("start_byte"), span.get("end_byte")
    if isinstance(s, int) and isinstance(e, int) and 0 <= s < e:
        return (s, e)
    return None


def _cited_loc_matches(sub_span, exp_span) -> bool:
    return (isinstance(sub_span, dict)
            and sub_span.get("source_location") == exp_span.get("source_location"))


def pinned_span_hash(source_location: str, s: int, e: int):
    if not source_location:
        return None
    fp = ROOT / source_location
    if not fp.is_file():
        return None
    raw = fp.read_bytes()
    if e > len(raw):
        return None
    return sha256_bytes(raw[s:e])


def score_one(sub: dict, key: dict, tolerance: int) -> dict:
    exp = key["expected_span"]
    availability = key["span_availability"]
    abstain_expected = bool(key["abstain_expected"])
    exp_answer = key["expected_answer"]
    abstained = _is_abstain(sub)
    cited = not abstained and _span_bounds(sub.get("span")) is not None

    # axis 1: answer correctness (only when an answer was given)
    answer_given = (not abstained) and isinstance(sub.get("answer"), str) \
        and sub.get("answer") != ""
    answer_correct = answer_given and (sub.get("answer") == exp_answer)

    # axis 3: citation exactness vs expected bounds (needs verifiable bounds)
    exp_bounds = _span_bounds({"start_byte": exp.get("start_byte"),
                               "end_byte": exp.get("end_byte")})
    exact = False
    if cited and exp_bounds is not None and availability == "verified":
        cs, ce = _span_bounds(sub["span"])
        es, ee = exp_bounds
        exact = (abs(cs - es) <= tolerance) and (abs(ce - ee) <= tolerance)

    # axis 4: span support -- recompute from the PINNED source at CITED bounds
    support = False
    if cited and availability == "verified" and exp.get("span_sha256"):
        if _cited_loc_matches(sub.get("span"), exp):
            cs, ce = _span_bounds(sub["span"])
            ph = pinned_span_hash(exp.get("source_location"), cs, ce)
            support = (ph is not None and ph == exp["span_sha256"])

    # axis 5: abstention
    if abstained and abstain_expected:
        abst = "correct_abstain"
    elif abstained and not abstain_expected:
        abst = "wrong_abstain"
    elif (not abstained) and abstain_expected:
        abst = "missed_abstain"
    else:
        abst = "valid_answer"

    return {
        "task_id": sub["task_id"],
        "availability": availability,
        "abstain_expected": abstain_expected,
        "axis_answer": {"attempted": answer_given, "correct": answer_correct},
        "axis_citation_existence": cited,
        "axis_citation_exactness": {"applicable": (cited and
                                                   exp_bounds is not None and
                                                   availability == "verified"),
                                    "exact": exact},
        "axis_span_support": {"applicable": (availability == "verified"),
                              "supported": support},
        "axis_abstention": abst,
        "cited_but_unsupported": cited and availability == "verified"
                                 and not support,
        "unsupported_but_cited": cited and availability == "unavailable",
    }


def _aggregate(per: list[dict]) -> dict:
    n = len(per)
    def cnt(pred):
        return sum(1 for r in per if pred(r))
    attempted = cnt(lambda r: r["axis_answer"]["attempted"])
    ans_correct = cnt(lambda r: r["axis_answer"]["correct"])
    cited = cnt(lambda r: r["axis_citation_existence"])
    exact_app = cnt(lambda r: r["axis_citation_exactness"]["applicable"])
    exact = cnt(lambda r: r["axis_citation_exactness"]["exact"])
    sup_app = cnt(lambda r: r["axis_span_support"]["applicable"])
    sup = cnt(lambda r: r["axis_span_support"]["supported"])
    abst = {}
    for k in ("correct_abstain", "wrong_abstain", "missed_abstain",
              "valid_answer"):
        abst[k] = cnt(lambda r, k=k: r["axis_abstention"] == k)
    return {
        "tasks": n,
        "answer_correctness": {
            "attempted": attempted, "correct": ans_correct,
            "accuracy_over_attempted": _r(ans_correct, attempted),
        },
        "citation_existence": {
            "cited": cited, "not_cited": n - cited,
            "rate": _r(cited, n),
        },
        "citation_exactness": {
            "applicable": exact_app, "exact": exact,
            "exact_rate_over_applicable": _r(exact, exact_app),
        },
        "span_support": {
            "applicable": sup_app, "supported": sup,
            "support_rate_over_applicable": _r(sup, sup_app),
        },
        "abstention": {
            "correct_abstain": abst["correct_abstain"],
            "wrong_abstain": abst["wrong_abstain"],
            "missed_abstain": abst["missed_abstain"],
            "valid_answer": abst["valid_answer"],
        },
        "cited_vs_supported_confusion": {
            "cited_and_supported": cnt(
                lambda r: r["axis_citation_existence"]
                and r["axis_span_support"]["supported"]),
            "cited_but_unsupported": cnt(lambda r: r["cited_but_unsupported"]),
            "unsupported_but_cited_on_abstain_task":
                cnt(lambda r: r["unsupported_but_cited"]),
            "not_cited_on_verifiable_task": abst["wrong_abstain"],
        },
    }


def _r(a, b):
    return round(a / b, 4) if b else None


# --------------------------------------------------------------------------
# Self-generated MECHANICAL BASELINES (not a real model result)
# --------------------------------------------------------------------------
def generate_baselines(keys: list[dict], seed: int, limit: int) -> dict:
    """Build submissions per strategy. Deterministic given seed.

    The subset is stratified so both span classes are exercised: at most half
    the budget goes to `verified` tasks (which test exactness + support) and the
    rest to `unavailable` tasks (which test abstention). Otherwise a
    first-N-by-id subset is almost all unavailable and never touches support.
    """
    ordered = sorted(keys, key=lambda k: k["task_id"])
    verified = [k for k in ordered if k["span_availability"] == "verified"]
    unavail = [k for k in ordered if k["span_availability"] == "unavailable"]
    n_ver = min(len(verified), max(1, limit // 2))
    n_unv = min(len(unavail), limit - n_ver)
    n_ver = min(len(verified), limit - n_unv)
    subset = verified[:n_ver] + unavail[:n_unv]
    strategies = {
        "exact_span": lambda k, i: _exact(k),
        "off_by_one_span": lambda k, i: _offbyone(k),
        "random_span": lambda k, i: _random(k, seed, i),
        "plausible_wrong_answer": lambda k, i: _plausiblewrong(k),
        "always_abstain": lambda k, i: {"task_id": k["task_id"], "abstain": True},
    }
    subs: dict[str, list[dict]] = {name: [] for name in strategies}
    for i, k in enumerate(subset):
        for name, fn in strategies.items():
            s = fn(k, i)
            s.setdefault("task_id", k["task_id"])
            subs[name].append(s)
    return {"keys_by_id": {k["task_id"]: k for k in subset}, "subs": subs,
            "subset_size": len(subset),
            "subset_verified": n_ver, "subset_unavailable": n_unv}


def _exact(k):
    exp = k["expected_span"]
    sp = {"source_location": exp.get("source_location"),
          "start_byte": exp.get("start_byte"), "end_byte": exp.get("end_byte")}
    return {"task_id": k["task_id"], "answer": k["expected_answer"], "span": sp}


def _offbyone(k):
    e = _exact(k)
    if isinstance(e["span"]["end_byte"], int):
        e["span"]["end_byte"] += 1
    return e


def _random(k, seed, i):
    e = _exact(k)
    h = int(hashlib.sha256(f"{seed}:{k['task_id']}".encode()).hexdigest()[:8], 16)
    s = h % 4096
    e["span"] = {"source_location": e["span"]["source_location"],
                 "start_byte": s, "end_byte": s + (h % 300 + 1)}
    return e


def _plausiblewrong(k):
    e = _exact(k)
    a = k["expected_answer"]
    idx = SEVERITIES.index(a) if a in SEVERITIES else 0
    e["answer"] = SEVERITIES[(idx + 1) % len(SEVERITIES)]
    return e


# --------------------------------------------------------------------------
def run(subs: list[dict], keys_by_id: dict, tolerance: int) -> dict:
    per = []
    skipped = 0
    for s in subs:
        k = keys_by_id.get(s["task_id"])
        if k is None:
            skipped += 1
            continue
        per.append(score_one(s, k, tolerance))
    return {"scored": len(per), "skipped_unknown_task": skipped,
            "metrics": _aggregate(per)}


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Four-axis + abstention scoring for evidence-span tasks.")
    ap.add_argument("--submissions",
                    help="jsonl of model outputs {task_id,answer,span|abstain}. "
                         "If omitted, run self-generated mechanical baselines.")
    ap.add_argument("--answer-key", default=str(AK))
    ap.add_argument("--tolerance", type=int, default=None,
                    help="citation exactness byte tolerance (default from manifest)")
    ap.add_argument("--baseline", action="store_true",
                    help="force the mechanical-baseline run (default when no "
                         "--submissions)")
    ap.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED)
    ap.add_argument("--check", action="store_true",
                    help="rebuild the report and fail (exit 1) if the "
                         "committed reports/span_scoring_report.json differs")
    args = ap.parse_args()

    if not Path(args.answer_key).is_file():
        V.log("score_span_tasks.py: answer key missing; run "
              "scripts/build_span_tasks.py first")
        return 2

    keys = _read_jsonl(Path(args.answer_key))
    tolerance = args.tolerance
    if tolerance is None:
        if MANIFEST.is_file():
            tolerance = json.loads(MANIFEST.read_text(encoding="utf-8")).get(
                "citation_exactness_tolerance_bytes", 0)
        else:
            tolerance = 0

    mode = "mechanical_baselines" if (args.baseline or not args.submissions) \
        else "external_submissions"
    report = {
        "generator": "scripts/score_span_tasks.py",
        "spec_item": "10 evidence-span citation scoring",
        "grading_axes": ["answer_correctness", "citation_existence",
                         "citation_exactness", "span_support", "abstention"],
        "axes_independent": True,
        "tolerance_bytes": tolerance,
        "mode": mode,
        "model_outputs_source": args.submissions or
            "none in repo (work/predict + reports/baseline are severity "
            "classifiers, not span citations); used SELF-GENERATED "
            "MECHANICAL BASELINES",
        "not_a_real_model_result": mode == "mechanical_baselines",
    }

    if mode == "mechanical_baselines":
        gen = generate_baselines(keys, args.seed, args.limit)
        report["baseline_note"] = (
            "Strategies are mechanical constructions (exact / off-by-one / "
            "random / plausible-wrong / always-abstain) to exercise each axis "
            "independently. They are NOT a model evaluation.")
        report["baseline_subset_size"] = gen["subset_size"]
        report["baseline_subset_verified"] = gen["subset_verified"]
        report["baseline_subset_unavailable"] = gen["subset_unavailable"]
        results = {}
        for name, subs in gen["subs"].items():
            results[name] = run(subs, gen["keys_by_id"], tolerance)
        report["results_by_strategy"] = results
        report["axis_separation_demo"] = _axis_separation(results)
        # persist baselines for reproducibility / inspection
        BASELINE_OUT.parent.mkdir(parents=True, exist_ok=True)
        lines = []
        for name in sorted(gen["subs"]):
            for s in sorted(gen["subs"][name], key=lambda x: x["task_id"]):
                rec = dict(s)
                rec["_strategy"] = name
                lines.append(json.dumps(rec, ensure_ascii=False, sort_keys=True))
        BASELINE_OUT.write_text("\n".join(lines) + "\n", encoding="utf-8",
                                 newline="\n")
        report["baseline_submissions"] = BASELINE_OUT.relative_to(
            ROOT).as_posix()
    else:
        subs = _read_jsonl(Path(args.submissions))
        keys_by_id = {k["task_id"]: k for k in keys}
        report["results"] = run(subs, keys_by_id, tolerance)

    md = _markdown(report)
    if args.check:
        jp = REPORTS / "span_scoring_report.json"
        mp = REPORTS / "span_scoring_report.md"
        want = canon_json_text(report)
        ok = jp.exists() and mp.exists() \
            and jp.read_text(encoding="utf-8") == want \
            and mp.read_text(encoding="utf-8") == md
        V.log("score_span_tasks.py --check OK" if ok else
              "score_span_tasks.py --check FAILED: committed report stale")
        return 0 if ok else 1

    REPORTS.mkdir(parents=True, exist_ok=True)
    (REPORTS / "span_scoring_report.json").write_text(
        canon_json_text(report), encoding="utf-8", newline="\n")
    (REPORTS / "span_scoring_report.md").write_text(md, encoding="utf-8",
                                                    newline="\n")
    V.log("score_span_tasks.py: wrote reports/span_scoring_report.{json,md} "
          f"(mode={mode})")
    return 0


def _axis_separation(results: dict) -> dict:
    """Show that the axes are independent by comparing strategies."""
    def m(name, path):
        r = results.get(name, {}).get("metrics", {})
        cur = r
        for p in path:
            cur = cur.get(p, {}) if isinstance(cur, dict) else None
        return cur
    return {
        "exact_span": {
            "answer_acc": m("exact_span", ["answer_correctness",
                                           "accuracy_over_attempted"]),
            "citation_rate": m("exact_span", ["citation_existence", "rate"]),
            "exactness": m("exact_span", ["citation_exactness",
                                          "exact_rate_over_applicable"]),
            "support": m("exact_span", ["span_support",
                                        "support_rate_over_applicable"]),
        },
        "off_by_one": {
            "answer_acc": m("off_by_one_span", ["answer_correctness",
                                                "accuracy_over_attempted"]),
            "citation_rate": m("off_by_one_span", ["citation_existence", "rate"]),
            "exactness": m("off_by_one_span", ["citation_exactness",
                                               "exact_rate_over_applicable"]),
            "support": m("off_by_one_span", ["span_support",
                                             "support_rate_over_applicable"]),
        },
        "plausible_wrong": {
            "answer_acc": m("plausible_wrong_answer", ["answer_correctness",
                                                       "accuracy_over_attempted"]),
            "support": m("plausible_wrong_answer", ["span_support",
                                                    "support_rate_over_applicable"]),
        },
        "note": ("off_by-one keeps answer + existence but breaks exactness AND "
                 "support -> the two citation axes are genuinely separate; "
                 "plausible-wrong keeps support but breaks answer correctness."),
    }


def _markdown(rep: dict) -> str:
    lines = ["# Span-task scoring report (spec item 10)", "",
             f"- mode: **{rep['mode']}**",
             f"- grading axes (independent): "
             f"{', '.join(rep['grading_axes'])}",
             f"- citation exactness tolerance: {rep['tolerance_bytes']} bytes",
             f"- model outputs source: {rep['model_outputs_source']}",
             f"- not a real model result: {rep['not_a_real_model_result']}",
             ""]
    if rep["mode"] == "mechanical_baselines":
        lines += [f"> {rep['baseline_note']}", "",
                  f"Baseline subset size: {rep['baseline_subset_size']} tasks "
                  f"({rep['baseline_subset_verified']} verified + "
                  f"{rep['baseline_subset_unavailable']} unavailable); "
                  f"submissions: `{rep['baseline_submissions']}`", ""]
        for name in sorted(rep["results_by_strategy"]):
            lines.append(_strategy_md(name, rep["results_by_strategy"][name]))
        lines += ["## Axis-separation demonstration", "",
                  "```json",
                  json.dumps(rep["axis_separation_demo"], indent=2,
                             sort_keys=True),
                  "```", ""]
    else:
        lines.append(_strategy_md("external", rep["results"]))
    return "\n".join(lines)


def _strategy_md(name: str, res: dict) -> str:
    mt = res["metrics"]
    a = mt["answer_correctness"]
    ce = mt["citation_existence"]
    cx = mt["citation_exactness"]
    ss = mt["span_support"]
    ab = mt["abstention"]
    cf = mt["cited_vs_supported_confusion"]
    return (
        f"## Strategy: {name}\n\n"
        f"scored={res['scored']} skipped={res['skipped_unknown_task']}\n\n"
        "| axis | value |\n|---|---|\n"
        f"| answer_correctness | {a['correct']}/{a['attempted']} "
        f"(acc={a['accuracy_over_attempted']}) |\n"
        f"| citation_existence | {ce['cited']}/{mt['tasks']} "
        f"(rate={ce['rate']}) |\n"
        f"| citation_exactness | {cx['exact']}/{cx['applicable']} "
        f"(rate={cx['exact_rate_over_applicable']}) |\n"
        f"| span_support | {ss['supported']}/{ss['applicable']} "
        f"(rate={ss['support_rate_over_applicable']}) |\n"
        f"| abstention | correct_abstain={ab['correct_abstain']} "
        f"wrong_abstain={ab['wrong_abstain']} "
        f"missed_abstain={ab['missed_abstain']} "
        f"valid_answer={ab['valid_answer']} |\n"
        f"| cited_vs_supported | supported={cf['cited_and_supported']} "
        f"cited_but_unsupported={cf['cited_but_unsupported']} "
        f"unsupported_but_cited_on_abstain_task="
        f"{cf['unsupported_but_cited_on_abstain_task']} "
        f"not_cited_on_verifiable={cf['not_cited_on_verifiable_task']} |\n")


if __name__ == "__main__":
    sys.exit(main())
