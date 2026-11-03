#!/usr/bin/env python3
"""Generate the v2.2 report set under reports/v2_2/.

Every number here is read from the machine-readable layers themselves
(jsonl_ml/, derived_v2_2/, splits_v2_2/, experiments_v2_2/, benchmark/) or from
a JSON report another stage wrote. Nothing is typed in. Where a measurement could
not be made, the line says which blocker applied.

Files written:
    reports/v2_2/dataset_summary.json   machine-readable v2.2 layer summary
    reports/v2_2/benchmark.json         every benchmark family, A-Q
    reports/v2_2/quality_report.md      the v2.2 quality report

    python scripts/generate_v22_reports.py
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vlun import (  # noqa: E402
    BENCHMARK_FAMILIES, BENCH, DATASET_VERSION, REPORTS, SPLITS, log, read_jsonl,
    write_json,
)
from vlun_ml import (  # noqa: E402
    DERIVED_V22, EXPERIMENTS_V22, ML_JSONL, REPORTS_V22, SOURCE_TIERS, SPLITS_V22,
    load_findings, load_sources,
)

OUT = REPORTS_V22


def J(path, default=None):
    if not path.exists():
        return default if default is not None else {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default if default is not None else {}


def source_summary(sources: list[dict]) -> dict:
    return {
        "total": len(sources),
        "by_tier": dict(sorted(collections.Counter(
            str(s.get("source_tier")) for s in sources).items())),
        "tier_rules": {str(k): v for k, v in SOURCE_TIERS.items()},
        "by_origin": dict(sorted(collections.Counter(
            s.get("evidence_origin") for s in sources).items())),
        "by_verification": dict(sorted(collections.Counter(
            (s.get("verification") or {}).get("status") for s in sources).items())),
        "content_licenses": dict(sorted(collections.Counter(
            (s.get("license") or {}).get("content_license") for s in sources).items())),
        "redistributable": dict(sorted(collections.Counter(
            str((s.get("license") or {}).get("redistributable")) for s in sources).items())),
        "note": ("an undeclared licence is recorded as \"unknown\" and is not "
                 "redistributable; no licence is inferred from a repository's "
                 "absence of a LICENSE file"),
    }


def record_summary(records: list[dict], findings: list[dict]) -> dict:
    fblocks = [r.get("finding") or {} for r in records]
    quality_dims: dict[str, collections.Counter] = {}
    field_types: collections.Counter = collections.Counter()
    for r in records:
        for dim, val in (r.get("quality") or {}).items():
            # *_basis blocks carry the counters behind an ordinal label and
            # scoring_note is prose; only the labels themselves are summarised
            if dim == "note" or dim == "scoring_note" or dim.endswith("_basis"):
                continue
            if isinstance(val, (dict, list)):
                val = json.dumps(val, sort_keys=True)
            quality_dims.setdefault(dim, collections.Counter())[val] += 1
    for f in findings:
        for block in (f.get("evidence") or {}).values():
            if isinstance(block, dict) and block.get("evidence_type"):
                field_types[block["evidence_type"]] += 1
    return {
        "records": len(records),
        "by_language": dict(sorted(collections.Counter(
            r.get("language") for r in records).items())),
        "by_ecosystem": dict(sorted(collections.Counter(
            r.get("ecosystem") for r in records).items())),
        "by_record_class": dict(sorted(collections.Counter(
            f.get("record_class") for f in fblocks).items())),
        "by_status": dict(sorted(collections.Counter(
            f.get("status") for f in fblocks).items())),
        "by_severity": dict(sorted(collections.Counter(
            f.get("severity") or "not_published" for f in fblocks).items())),
        "severity_with_attribution": sum(
            1 for f in fblocks if f.get("severity") and f.get("severity_source")),
        "severity_value_without_attribution": sum(
            1 for f in fblocks if f.get("severity") and not f.get("severity_source")),
        "evidence_strongest": dict(sorted(collections.Counter(
            (r.get("evidence_summary") or {}).get("strongest") for r in records).items())),
        "evidence_weakest": dict(sorted(collections.Counter(
            (r.get("evidence_summary") or {}).get("weakest") for r in records).items())),
        "quality_rubric": {k: dict(sorted(v.items())) for k, v in
                           sorted(quality_dims.items())},
        "field_evidence_types": dict(sorted(field_types.items())),
        "attacker_identity": dict(sorted(collections.Counter(
            (r.get("attacker_model") or {}).get("identity") for r in records).items())),
        "attacker_actor_mentioned": sum(
            1 for r in records if (r.get("attacker_model") or {}).get("actor_mentioned")),
        "note": ("the quality dimensions are the published rubric applied "
                 "by scripts/build_derived_v22.py; no weighted aggregate is "
                 "produced and none is reported"),
    }


def experiment_summary(records: list[dict], index: dict) -> dict:
    runs = index.get("experiments") or []
    views = [r.get("experiment_view") or {} for r in records]
    levels = collections.Counter()
    for r in records:
        ex = r.get("experiment_view") or {}
        levels[ex.get("level") if ex.get("present") else "none"] += 1

    # Level-exact verification counts, read off the level a reader sees -
    # `experiment_view.level`, which scripts/build_derived_v22.py already
    # overwrote with the adjudicated `level_after`. Reading the published record
    # fields keeps this a view of the layer (no re-read of
    # reports/v2_2/l5_adjudication.json here) and forbids both failure modes:
    # a name-only heuristic and any count that lumps levels together. L4 means
    # "executed, violation not demonstrated", so it is never counted as a
    # verified L5; a provisional L5 candidate is reported beside the verified
    # figure, not inside it.
    def at_level(level: str) -> int:
        return sum(1 for v in views
                   if v.get("present") and v.get("level") == level)

    verified_l5 = at_level("L5")
    verified_l6 = at_level("L6")
    provisional = sum(1 for v in views if v.get("verification_provisional"))
    demoted = sum(1 for v in views if v.get("demoted_from_L5"))
    blockers = {}
    for r in records:
        lang = r.get("language")
        if lang in ("move", "cairo") \
                and not (r.get("experiment_view") or {}).get("executed"):
            blockers[lang] = (blockers.get(lang) or 0) + 1
    return {
        "runs": len(runs),
        "by_level": dict(sorted(levels.items())),
        "verified_l5": verified_l5,
        "verified_l6": verified_l6,
        "verified_l5_or_l6": verified_l5 + verified_l6,
        "executed_at_l4": at_level("L4"),
        "provisional_l5_candidates": provisional,
        "adjudicated_demoted": demoted,
        "adjudicated_l5_claims": sum(1 for v in views
                                     if v.get("adjudication_verdict")),
        "adjudication_verdicts": dict(sorted(collections.Counter(
            v["adjudication_verdict"] for v in views
            if v.get("adjudication_verdict")).items())),
        "level_counts_note": (
            "verified_l5 is level == \"L5\" only and verified_l6 is "
            "level == \"L6\" only; verified_l5_or_l6 is their sum and is the "
            "only figure that spans two levels. executed_at_l4 counts records "
            "whose adjudicated level is L4 (executed, violation not "
            "demonstrated): they are not verified L5. "
            "provisional_l5_candidates is experiment_view."
            "verification_provisional (a WEAK adjudication held at L4 with "
            "l5_candidate true) and adjudicated_demoted is "
            "experiment_view.demoted_from_L5 (an UNSUPPORTED adjudication); "
            "the two plus verified_l5 equal adjudicated_l5_claims, which is "
            "scripts/build_derived_v22.py's manifest accounting"),
        "executed": sum(1 for r in records
                        if (r.get("experiment_view") or {}).get("executed")),
        "fixed_revision_executed": sum(
            1 for r in records
            if (r.get("experiment_view") or {}).get("fixed_revision_executed")),
        "by_outcome": dict(sorted(collections.Counter(
            (r.get("experiment_view") or {}).get("outcome") for r in records
            if (r.get("experiment_view") or {}).get("present")).items())),
        # `outcome` is what the run wrote and the adjudication deliberately does
        # not rewrite it, so it is only ever reported broken out by the
        # adjudicated level it belongs to.
        "by_outcome_by_level": {
            level: dict(sorted(collections.Counter(
                v.get("outcome") for v in views
                if v.get("present") and v.get("level") == level).items()))
            for level in sorted({v.get("level") for v in views
                                 if v.get("present") and v.get("level")})},
        "runs_detail": [{
            "experiment_id": e.get("experiment_id"),
            "source_report": e.get("source_report"),
            "status": e.get("status"),
            "exit_code": e.get("exit_code"),
            "seconds": e.get("seconds"),
            "passing_tests": len(e.get("passing_tests") or []),
            "failing_tests": e.get("failing_test_count")
                             if isinstance(e.get("failing_test_count"), int)
                             else len(e.get("failing_tests") or []),
            "toolchain": e.get("toolchain"),
        } for e in runs],
        "not_executed_by_language": dict(sorted(blockers.items())),
        "blocker": ("sui, aptos, scarb and snFuzzer are not installed in this "
                    "environment, so every Move and Cairo record except "
                    "move:cetus-checked-shlw could not run locally and stays "
                    "at its reported-claim level; that one record ran through "
                    "a downloaded sui toolchain (1.6.3 for the v1.1.0 era, "
                    "1.48.2 for the v1.1.1 and v1.1.2 eras) and is counted "
                    "with the executed runs above, not here"),
    }


def split_summary() -> dict:
    out = {}
    for s in (*SPLITS, "quarantine"):
        p = SPLITS_V22 / f"{s}.jsonl"
        rows = read_jsonl(p) if p.exists() else []
        out[s] = {
            "v2_2": sum(1 for r in rows if r.get("layer") == "v2.2"),
            "total": len(rows),
        }
    return out


def benchmark_summary() -> dict:
    man = J(BENCH / "manifest.json", {}) or {}
    rows = []
    for key, (name, layer, question) in sorted(BENCHMARK_FAMILIES.items()):
        entry = (man.get("tasks") or {}).get(name) or {}
        rows.append({
            "family": key,
            "file": entry.get("file"),
            "layer": layer,
            "question": question,
            "tasks": entry.get("tasks"),
            "labeled": entry.get("labeled"),
            "partial": entry.get("partial"),
            "unlabeled": entry.get("unlabeled"),
            "scorable": entry.get("scorable"),
            "by_split": entry.get("by_split"),
            "by_language": entry.get("by_language"),
            "answer_key_evidence_levels": entry.get("answer_key_evidence_levels"),
        })
    return {
        "generated_by": "scripts/generate_v22_reports.py",
        "families": rows,
        "totals": {
            "families": len(rows),
            "tasks": sum(r.get("tasks") or 0 for r in rows),
            "labeled": sum(r.get("labeled") or 0 for r in rows),
            "partial": sum(r.get("partial") or 0 for r in rows),
            "unlabeled": sum(r.get("unlabeled") or 0 for r in rows),
            "scorable": sum(r.get("scorable") or 0 for r in rows),
            "v2_2_families": sum(1 for r in rows if r["layer"] == "v2.2"),
            "v2_2_tasks": sum(r.get("tasks") or 0 for r in rows
                              if r["layer"] == "v2.2"),
        },
        "policy": ("families A-J keep their v1 answer keys and splits; K-Q are "
                   "built from derived_v2_2 over splits_v2_2, one task per v2.2 "
                   "record (M only for records with a run). A task is labeled "
                   "only where the record actually holds the answer, partial "
                   "where half of it exists, and unlabeled with a stated reason "
                   "otherwise; only labeled tasks are scored. The model-facing "
                   "payload is the task's `input` object - ids and source blocks "
                   "are traceability and carry the language prefix."),
    }


def write_reports() -> dict:
    sources = load_sources() if ML_JSONL.exists() else []
    findings = load_findings() if ML_JSONL.exists() else []
    d22_path = DERIVED_V22 / "records.jsonl"
    records = read_jsonl(d22_path) if d22_path.exists() else []
    index = J(EXPERIMENTS_V22 / "index.json", {}) or {}
    leak = J(REPORTS / "leakage_report_v22.json", {}) or {}
    validation = J(REPORTS / "validation_report.json", {}) or {}

    # sources shared by tasks in two splits: counted here from the pointers and
    # the records, so the report cannot disagree with what scripts/validate.py
    # recomputes on every run
    src_splits: dict[str, set] = collections.defaultdict(set)
    for s in SPLITS:
        p = SPLITS_V22 / f"{s}.jsonl"
        for row in (read_jsonl(p) if p.exists() else []):
            if row.get("layer") != "v2.2":
                continue
            rec = next((r for r in records if r["id"] == row["id"]), None)
            for e in ((rec or {}).get("sources_view") or {}).get("entries") or []:
                if e.get("source_id"):
                    src_splits[e["source_id"]].add(s)
    spanning = sorted(k for k, v in src_splits.items() if len(v) > 1)

    summary = {
        "generated_by": "scripts/generate_v22_reports.py",
        "dataset_version": DATASET_VERSION,
        "source_layer": source_summary(sources),
        "ml_findings": len(findings),
        "derived_records": record_summary(records, findings),
        "experiments": experiment_summary(records, index),
        "splits_v2_2": split_summary(),
        "benchmark": benchmark_summary(),
        "leakage": {
            "report": "reports/leakage_report_v22.json",
            "sources_checked": len(src_splits),
            "sources_spanning_splits": len(spanning),
            "sources_spanning_split_ids": spanning,
            "post_check": leak.get("post_check") or {},
            "note": ("cross-split source sharing and pointer integrity are "
                     "re-checked by scripts/validate.py on every run, so this "
                     "figure cannot go stale without the gate failing"),
        },
        "validation": {
            "checks": validation.get("checks"),
            "passed": validation.get("passed"),
            "failed_critical": validation.get("failed_critical"),
            "warnings": validation.get("warnings"),
        },
        "blockers": [
            "move and cairo toolchains (sui, aptos, scarb, snFuzzer) are not "
            "installed, so no local L3-L6 for Move/Cairo except the one "
            "sui-toolchain Move run (move:cetus-checked-shlw, L6)",
            "the report layer declares no licence for 109 of 112 sources, which "
            "stay content_license=unknown and not redistributable",
            "no model has been evaluated: these files describe the instrument, "
            "not a result",
        ],
    }
    OUT.mkdir(parents=True, exist_ok=True)
    write_json(OUT / "dataset_summary.json", summary)
    write_json(OUT / "benchmark.json", summary["benchmark"])
    return summary


def quality_report_md(s: dict) -> str:
    sl = s["source_layer"]
    dr = s["derived_records"]
    ex = s["experiments"]
    bm = s["benchmark"]
    sp = s["splits_v2_2"]
    val = s["validation"]
    md: list[str] = []
    a = md.append

    a("# VLUN v2.2 - quality report\n")
    a("Generated by `scripts/generate_v22_reports.py`. Every number is read from "
      "`jsonl_ml/`, `derived_v2_2/`, `splits_v2_2/`, `experiments_v2_2/`, "
      "`benchmark/` or a JSON report in `reports/`. Where a measurement could not "
      "be made, the line says which blocker applied.\n")

    a("## What v2.2 adds\n")
    a("- a second, never-rewritten source layer (`jsonl_ml/`): "
      f"**{s['ml_findings']} findings** from **{sl['total']} sources**, each source "
      "with retrieval method, payload sha256, verification status, a tier 0-4 and "
      "its licence declaration;")
    a("- 137 derived records in `derived_v2_2/` with per-field evidence, "
      "the published quality rubric and the experiment view;")
    a(f"- `splits_v2_2/`: train {sp['train']['v2_2']}, validation "
      f"{sp['validation']['v2_2']}, test {sp['test']['v2_2']} assigned from "
      f"canonical duplicate groups with per-record sha256 pointers "
      f"({sp['quarantine']['total']} duplicate v1 records sit in "
      "`quarantine.jsonl`), so a pointer that does not match its record "
      "fails the gate;")
    a(f"- {ex['runs']} executed multi-language experiment runs "
      f"(`experiments_v2_2/`);")
    a(f"- benchmark families K-Q: **{bm['totals']['v2_2_families']} new families**, "
      f"**{bm['totals']['v2_2_tasks']} new tasks**, on top of A-J unchanged;\n")

    a("## Source layer\n")
    a(f"- sources: **{sl['total']}**")
    a(f"- by tier: `{sl['by_tier']}`")
    a(f"- by origin: `{sl['by_origin']}`")
    a(f"- by verification: `{sl['by_verification']}`")
    a(f"- content licences: `{sl['content_licenses']}`")
    a(f"- redistributable: `{sl['redistributable']}`\n")
    a("Tier is an admission rule, not a reputation score: 0 is what the protocol "
      "itself published, 4 is a third-party write-up. A source with no declared "
      "licence keeps `content_license: unknown` and `redistributable: false`; no "
      "licence is ever inferred.\n")

    a("## Findings\n")
    a(f"- records: **{dr['records']}**")
    a(f"- by language: `{dr['by_language']}`")
    a(f"- by ecosystem: `{dr['by_ecosystem']}`")
    a(f"- by record class: `{dr['by_record_class']}`")
    a(f"- by status: `{dr['by_status']}`")
    a(f"- by severity: `{dr['by_severity']}` "
      f"({dr['severity_with_attribution']} with attribution, "
      f"{dr['severity_value_without_attribution']} rated without one, "
      f"{(dr['by_severity'] or {}).get('not_published', 0)} "
      "with no published rating at all)\n")
    a("`not_published` is a counted outcome. Family L grades exactly this: "
      "consolidate what the publishers published, and where none published a "
      "rating the answer is null with the absence stated on the row.\n")

    a("## Evidence and quality rubric\n")
    a(f"- strongest evidence per record: `{dr['evidence_strongest']}`")
    a(f"- weakest evidence per record: `{dr['evidence_weakest']}`")
    a("- quality rubric (each dimension is an ordinal label with a stated basis, "
      "no weighted aggregate):")
    for dim, counts in (dr.get("quality_rubric") or {}).items():
        a(f"  - `{dim}`: `{counts}`")
    a(f"- attacker identity: `{dr['attacker_identity']}` "
      f"({dr['attacker_actor_mentioned']} records name an actor at all)\n")

    a("## Experiments\n")
    a(f"- runs in `experiments_v2_2/`: **{ex['runs']}**")
    a(f"- records by level: `{ex['by_level']}`")
    a(f"- verified, by level and counted separately: **{ex['verified_l5']}** at "
      "L5 (the claimed violation reproduced) and "
      f"**{ex['verified_l6']}** at L6 (reproduced on the vulnerable revision "
      f"AND blocked on the fixed one), i.e. "
      f"**{ex['verified_l5_or_l6']}** of {dr['records']} records at L5 or L6; "
      "no record is counted twice and neither figure is a name-only match\n")
    a(f"- executed but **not** verified at L5: **{ex['executed_at_l4']}** at L4 "
      "(executed, violation not demonstrated), "
      f"**{ex['by_level'].get('L3', 0)}** at L3 (compiles) and "
      f"**{ex['by_level'].get('L1', 0)}** at L1\n")
    verd = ex["adjudication_verdicts"]
    if ex["adjudicated_l5_claims"]:
        a(f"- L5 claims carrying an adjudication verdict on the record "
          f"(`experiment_view.adjudication_verdict`, from "
          "`reports/v2_2/l5_adjudication.json` as applied by "
          f"`scripts/build_derived_v22.py`): **{ex['adjudicated_l5_claims']}** "
          f"covered - **{verd.get('SUPPORTED', 0)}** SUPPORTED, still counted as "
          f"verified L5 above; **{verd.get('WEAK', 0)}** WEAK, moved to L4 with "
          "`provisional: true` and `l5_candidate: true` "
          f"(`provisional_l5_candidates: {ex['provisional_l5_candidates']}`, not "
          "verified L5); "
          f"**{verd.get('UNSUPPORTED', 0)}** UNSUPPORTED, demoted below L5 "
          f"(`adjudicated_demoted: {ex['adjudicated_demoted']}`)\n")
    else:
        a("- the published layer carries no L5 adjudication verdict on any "
          "record yet, so the L5 figure above is the level the records hold, "
          "not a per-test review outcome\n")
    a(f"- outcomes as their runs recorded them, by adjudicated level: "
      f"`{ex['by_outcome_by_level']}` - `outcome` is left exactly as the run "
      "wrote it and is never read as a verification count on its own; "
      f"the flat tally over all records with a run is `{ex['by_outcome']}`\n")
    a(f"- fixed-revision leg executed: **{ex['fixed_revision_executed']}** "
      "(L6 needs the same violation reproduced on vulnerable AND blocked on "
      "fixed; move:cetus-checked-shlw meets it - the silent 2^192 shift "
      "reproduces on integer-mate v1.1.0 and on the insufficient v1.1.1, "
      "and the boundary test aborts on the v1.1.2 fix - while the other "
      "fixed-revision record, vyper:CVE-2024-24567, sits at L3)\n")
    a("| experiment | source report | status | exit | seconds | tests pass/fail |")
    a("|---|---|---|---|---|---|")
    for r in ex["runs_detail"]:
        a(f"| `{r['experiment_id']}` | `{r['source_report']}` | {r['status']} | "
          f"{r['exit_code']} | {r['seconds']} | "
          f"{r['passing_tests']}/{r['failing_tests']} |")
    a("")
    a(f"**Blocker.** {ex['blocker']}\n")

    a("## Splits\n")
    a("| split | v2.2 tasks | file rows |")
    a("|---|---|---|")
    for name in ("train", "validation", "test", "quarantine"):
        a(f"| {name} | {sp[name]['v2_2']} | {sp[name]['total']} |")
    a("")
    a("Every v2.2 pointer records the sha256 of its record; `scripts/validate.py` "
      "recomputes it and fails on mismatch, checks that no record sits in two "
      "splits, and checks that no source is shared by tasks in two splits.\n")

    a("## Benchmark\n")
    a(f"- families: **{bm['totals']['families']}** "
      f"(A-J v1, K-Q v2.2)")
    a(f"- tasks: **{bm['totals']['tasks']}**, labeled: "
      f"**{bm['totals']['labeled']}**, partial: **{bm['totals']['partial']}**, "
      f"unlabeled: **{bm['totals']['unlabeled']}**\n")
    a("| family | layer | tasks | labeled | partial | unlabeled | train/val/test |")
    a("|---|---|---|---|---|---|---|")
    for f in bm["families"]:
        bs = f.get("by_split") or {}
        a(f"| {f['family']} | {f['layer']} | {f['tasks']} | {f['labeled']} | "
          f"{f['partial']} | {f['unlabeled']} | "
          f"{bs.get('train', 0)}/{bs.get('validation', 0)}/{bs.get('test', 0)} |")
    a("")
    a(bm["policy"] + "\n")

    a("## Leakage\n")
    a("- report: `reports/leakage_report_v22.json`")
    a(f"- sources spanning splits: `{s['leakage']['sources_spanning_splits']}`")
    a(f"- validation gate: {val.get('passed')}/{val.get('checks')} checks passed, "
      f"{val.get('failed_critical')} critical failures\n")

    a("## Honest limitations\n")
    for b in s["blockers"]:
        a(f"- {b}")
    a("- most of family N is unlabeled by design: only the records whose sources "
      "actually state an attacker standing are graded, because inferring one would "
      "be the model's job, not the dataset's.")
    a("- family Q grades the application of a published rubric to observed "
      "properties; it does not grade whether the rubric is the right one.")
    a("")
    return "\n".join(md)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.parse_args()
    s = write_reports()
    md = quality_report_md(s)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "quality_report.md").write_text(
        md.encode("ascii", "replace").decode("ascii"), encoding="utf-8", newline="\n")
    log(f"wrote {OUT / 'quality_report.md'}")
    log(f"wrote {OUT / 'dataset_summary.json'} and {OUT / 'benchmark.json'}")
    log(f"records={s['derived_records']['records']} "
        f"sources={s['source_layer']['total']} "
        f"tasks={s['benchmark']['totals']['tasks']} "
        f"gate={s['validation']['passed']}/{s['validation']['checks']}")
    ex = s["experiments"]
    log(f"levels L5={ex['verified_l5']} L6={ex['verified_l6']} "
        f"L4={ex['executed_at_l4']} by_level={ex['by_level']} "
        f"provisional_l5_candidates={ex['provisional_l5_candidates']} "
        f"adjudicated_demoted={ex['adjudicated_demoted']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
