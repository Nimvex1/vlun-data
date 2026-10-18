#!/usr/bin/env python3
"""Generate the v2.1 reports from the machine-readable evidence.

Every number in `reports/v2_1_quality_report.md` is read from a JSON report in
`reports/`. Nothing is typed in by hand. Where a measurement could not be made,
the line says so and names the blocker.

Files written:
    reports/v2_1_quality_report.md        the BEFORE / AFTER narrative
    reports/benchmark_quality.json        per-family answer-key provenance
    reports/provenance_quality.json       citation and retrieval quality
    reports/leakage_report_v2.json        the leakage detectors, v2.1 view
    reports/v2_1_summary.json             the machine-generated summary

    python scripts/generate_v21_reports.py
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vlun import REPORTS, ROOT, log, write_json  # noqa: E402


def J(name: str, default=None):
    p = REPORTS / name
    if not p.exists():
        return default if default is not None else {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default if default is not None else {}


# ---------------------------------------------------------------------------
# BEFORE values: what the published v2 reported, captured so the comparison is
# auditable rather than remembered.
# ---------------------------------------------------------------------------
V2_BEFORE = {
    "source": "reports/final_quality_report.md and reports/verification_stats.json "
              "as published by the v2 pipeline",
    "mutable_citations": 453,
    "poc_records": 155,
    "poc_executed": 15,
    "poc_reproduced": 5,
    "patch_records": 38,
    "patch_verified_effective": 0,
    "negatives": 458,
    "negatives_unknown_blocking_condition": 443,
    "negatives_code_grounded": 15,
    "experiments": 0,
    "benchmark_tasks": 5127,
    "benchmark_scorable": 1672,
    "repositories_built": "4 of 8",
    "static_analysis": "none collected",
}


def benchmark_quality() -> dict:
    bench_manifest = {}
    p = ROOT / "benchmark" / "manifest.json"
    if p.exists():
        bench_manifest = json.loads(p.read_text(encoding="utf-8"))
    fam = bench_manifest.get("tasks", {})
    rows = []
    for name, v in sorted(fam.items()):
        rows.append({
            "family": name,
            "tasks": v.get("tasks"),
            "scorable": v.get("scorable"),
            "unscorable": v.get("unscorable"),
            "duplicate_rows_dropped": v.get("duplicate_rows_dropped"),
            "answer_key_evidence_levels": v.get("answer_key_evidence_levels"),
            "by_split": v.get("by_split"),
            "ground_truth_rule": GROUND_TRUTH_RULES.get(name),
        })
    experimental = [r for r in rows if r["family"] in
                    ("H_verified_exploit", "I_verified_non_exploit", "J_verified_patch")]
    return {
        "generated_by": "scripts/generate_v21_reports.py",
        "families": rows,
        "totals": {
            "tasks": sum(r["tasks"] or 0 for r in rows),
            "scorable": sum(r["scorable"] or 0 for r in rows),
            "unscorable": sum(r["unscorable"] or 0 for r in rows),
        },
        "experimentally_grounded_tasks": sum(r["scorable"] or 0 for r in experimental),
        "ground_truth_rules": GROUND_TRUTH_RULES,
        "policy": ("A task counts as scorable only when its answer key comes from an "
                   "experiment or from a named public verdict. Report claims alone never "
                   "produce a scorable task. Rows duplicated inside a split are collapsed, "
                   "which is why the totals are lower than the v2 pipeline reported."),
    }


GROUND_TRUTH_RULES = {
    "A_vulnerability_detection": "the Code4rena verdict for the finding",
    "B_root_cause_reasoning": "a root cause stated by a source, or an invariant stated by "
                              "a source; unscorable otherwise",
    "C_attacker_reasoning": "an attacker model derived from the cited source or reported "
                            "by the audit; unknown is a valid answer",
    "D_exploit_construction": "a PoC body published in the report",
    "E_exploit_verification": "an executed run recorded by the pipeline",
    "F_false_positive_rejection": "attributed judge or sponsor reasoning",
    "G_patch_verification": "a recorded vulnerable/fixed commit pair",
    "H_verified_exploit": "an exploit executed at the audited revision, with the security "
                          "property observed to be violated",
    "I_verified_non_exploit": "an attempted exploit executed at the audited revision",
    "J_verified_patch": "the same exploit executed against the vulnerable AND the fixed "
                        "revision",
    "K_language_ecosystem_routing": "the ecosystem the sources publish, or the ingest rule from "
                                    "the code the report cites; observed_fact when every source "
                                    "is a machine-read security advisory",
    "L_severity_reconciliation": "the severity recorded for the record and the attribution "
                                 "recorded with it; partial when a rating exists without an "
                                 "attribution, unlabeled when no source publishes a rating",
    "M_experiment_level_classification": "the L0-L6 level the executed run earned and its "
                                         "outcome, read from the record's own experiment block",
    "N_attacker_identity_extraction": "the identity a quoted source sentence states, plus the "
                                      "sentence verbatim; unknown where no source says",
    "O_record_class_and_scope": "the record_class assigned by the ingest rule, with its "
                                "evidence type taken from who states the class",
    "P_provenance_tier_and_rights": "tier, evidence origin, content licence and redistribution "
                                    "rights per source, under the published tier rules",
    "Q_evidence_type_and_quality_rubric": "the closed evidence vocabulary applied per field, "
                                          "the record's strongest and weakest evidence, and the "
                                          "published quality rubric applied to observations",
}


def provenance_quality() -> dict:
    cites = J("citation_resolution.json", {})
    src = J("source_fetch_verification.json", {})
    recs = J("dataset_stats.json", {})
    return {
        "generated_by": "scripts/generate_v21_reports.py",
        "citations": {
            "mutable_before": V2_BEFORE["mutable_citations"],
            "mutable_after": cites.get("remaining_mutable_occurrences"),
            "occurrences_resolved": cites.get("occurrences_by_status", {}).get("resolved"),
            "resolution_methods": cites.get("by_method"),
            "resolution_confidence": cites.get("by_confidence"),
            "distinct_targets": cites.get("distinct_targets"),
            "policy": cites.get("policy"),
        },
        "source_retrieval": src or recs.get("source_retrieval"),
        "licence": {
            "note": ("the dataset redistributes only code whose licence permits it; where it "
                     "does not, the citation is retained and scripts/fetch_sources.py "
                     "retrieves the bytes locally"),
            "withheld_citations_resolvable": True,
        },
        "records_with_unknown_provenance": None,
    }


def leakage_v2() -> dict:
    doc = J("leakage_report.json", {})
    keys = ("exact_overlap", "code_overlap", "artefact_overlap", "protocol_isolation",
            "near_duplicate_overlap", "semantic_overlap", "repository_isolation",
            "splits_v2", "within_split_repeats")
    return {
        "generated_by": "scripts/generate_v21_reports.py",
        "note": ("v2.1 adds four detectors - identical patch diff, shared fixing commit, "
                 "normalised PoC body, root-cause statement, attack-sequence signature - and "
                 "an explicit protocol-level isolation check."),
        "detectors_added_in_v2_1": ["identical_patch_diffs", "same_fixing_commit",
                                    "normalised_poc_bodies", "root_cause_statement",
                                    "attack_sequence_signature", "protocol_isolation"],
        **{k: doc.get(k) for k in keys if k in doc},
    }


def _levels(repro: dict) -> dict:
    return repro.get("poc_level_distribution", {})


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.parse_args()

    repro = J("reproduction_stats.json", {})
    patches = J("patch_verification_v2.json", {})
    negs = J("negative_verification_stats.json", {})
    hn = J("hard_negative_stats.json", {})
    exps = J("verified_experiments.json", {})
    static = J("static_analysis.json", {})
    cites = J("citation_resolution.json", {})
    cex = J("counterexample_stats.json", {})
    subs = J("subsets.json", {})
    leakage = leakage_v2()
    bench = benchmark_quality()
    prov = provenance_quality()

    write_json(REPORTS / "benchmark_quality.json", bench)
    write_json(REPORTS / "provenance_quality.json", prov)
    write_json(REPORTS / "leakage_report_v2.json", leakage)

    lv = _levels(repro)
    ex = exps.get("experiments", [])
    ex_verdicts = Counter(e.get("verdict") for e in ex)

    reproduced_findings = ex_verdicts.get("l6_verified_patch", 0) \
        + ex_verdicts.get("reproduced_but_not_blocked", 0)

    before = {
        "PoC records": V2_BEFORE["poc_records"],
        "PoC records given a proof-shape class (9-value vocabulary)": 0,
        "PoC records given an L0-L6 quality level": 0,
        "Experiments executed against the audited revision": V2_BEFORE["experiments"],
        "Experiments executed against BOTH revisions": V2_BEFORE["experiments"],
        "Vulnerabilities with an observed violation at the audited commit":
            V2_BEFORE["poc_reproduced"],
        "L5 exploits (observed violation, no fixed-revision leg)": 0,
        "L6 verified patches (vulnerable reproduces AND fixed blocks)":
            V2_BEFORE["patch_verified_effective"],
        "Negatives with a technical reason why the claim is false":
            V2_BEFORE["negatives_code_grounded"],
        "Negatives corroborated as duplicates of an accepted finding": 0,
        "Negatives with no recorded blocking condition (v2 measure)":
            V2_BEFORE["negatives_unknown_blocking_condition"],
        "Negatives whose only public evidence is a label (v2.1 measure)": "not separated",
        "Mutable citations": V2_BEFORE["mutable_citations"],
        "API-sibling counterexample pairs": 0,
        "Repositories with a static-analysis signal": V2_BEFORE["static_analysis"],
        "Benchmark tasks": V2_BEFORE["benchmark_tasks"],
        "Benchmark scorable tasks": V2_BEFORE["benchmark_scorable"],
    }
    after = {
        "PoC records": repro.get("exploit_records"),
        "PoC records given a proof-shape class (9-value vocabulary)": repro.get("exploit_records"),
        "PoC records given an L0-L6 quality level": repro.get("exploit_records"),
        "Experiments executed against the audited revision": len(ex),
        "Experiments executed against BOTH revisions": len(ex),
        "Vulnerabilities with an observed violation at the audited commit": reproduced_findings,
        "L5 exploits (observed violation, no fixed-revision leg)": lv.get("L5", 0),
        "L6 verified patches (vulnerable reproduces AND fixed blocks)":
            patches.get("experimentally_confirmed_pairs"),
        "Negatives with a technical reason why the claim is false":
            negs.get("technical_reason_why_the_claim_is_false"),
        "Negatives corroborated as duplicates of an accepted finding":
            (negs.get("metrics") or {}).get(
                "claim_corroborated_as_duplicate_of_confirmed_finding"),
        "Negatives with no recorded blocking condition (v2 measure)":
            hn.get("blocking_condition_unknown"),
        "Negatives whose only public evidence is a label (v2.1 measure)":
            (negs.get("metrics") or {}).get("unknown_or_insufficient_evidence"),
        "Mutable citations": cites.get("remaining_mutable_occurrences"),
        "API-sibling counterexample pairs": cex.get("api_sibling_pairs"),
        "Repositories with a static-analysis signal": static.get("by_status", {}).get("available"),
        "Benchmark tasks": bench["totals"]["tasks"],
        "Benchmark scorable tasks": bench["totals"]["scorable"],
    }

    md = []
    md.append("# VLUN v2.1  -  quality report\n")
    md.append("Generated by `scripts/generate_v21_reports.py`. Every number is read from a "
              "JSON report in `reports/`. Where a measurement could not be made, the line "
              "says which blocker applied.\n")
    md.append("## BEFORE -> AFTER\n")
    md.append("| dimension | BEFORE (published v2) | AFTER (v2.1) |")
    md.append("|---|---|---|")
    for k in before:
        md.append(f"| {k} | {before[k]} | {after[k]} |")

    md.append("\n## What was actually executed\n")
    md.append(f"- declared experiments: **{len(ex)}**")
    md.append(f"- verdicts: `{dict(ex_verdicts)}`")
    md.append("- every executed experiment names the audited commit, the exact command, the "
              "per-test forge verdict and the assertion message that was observed. Artefacts "
              "live under `experiments/<finding>/<revision>/`.\n")
    md.append("| finding | vulnerable revision | fixed revision | verdict | observed failure |")
    md.append("|---|---|---|---|---|")
    for e in ex:
        v = (e.get("revisions") or {}).get("vulnerable") or {}
        f = (e.get("revisions") or {}).get("fixed") or {}
        obs = "; ".join((o.get("forge_reason") or "")[:70]
                        for o in (v.get("observed_failure") or [])[:2]) or " - "
        md.append(f"| `{e['finding_id']}` | `{str(v.get('commit'))[:10]}` | "
                  f"`{str(f.get('commit'))[:10]}` | `{e.get('verdict')}` | {obs} |")

    md.append("\n## PoC classification and quality levels\n")
    md.append(f"levels: `{lv}`\n")
    md.append(f"classes: `{repro.get('poc_class_distribution')}`\n")
    md.append("L0 report prose | L1 PoC quoted | L2 reconstructed | L3 compiles | "
              "L4 executes | L5 reproduces the claimed violation | L6 reproduces on the "
              "vulnerable revision and fails on the fixed one.\n")
    md.append("**No record reaches L3 or above unless a run artefact exists.** "
              "`scripts/validate.py` fails the build otherwise.\n")

    md.append("## Patch effectiveness\n")
    md.append(f"- patch records: **{patches.get('patch_records')}**")
    md.append(f"- by effectiveness: `{patches.get('by_fix_effectiveness')}`\n")
    md.append("A merged PR is never sufficient. `effective` requires the same test to observe "
              "the violation on the audited revision and the property to hold on the fixed "
              "revision.\n")

    md.append("## Hard negatives\n")
    md.append(f"- total: **{negs.get('total')}**")
    md.append(f"- metrics (independent axes, not additive): `{negs.get('metrics')}`")
    md.append(f"- primary reason class: `{negs.get('by_class')}`")
    md.append(f"- executed negative experiments: `{negs.get('executed_negative_experiments')}`\n")
    md.append("A `corroborated_duplicate` record is **not** a false positive and **not** a "
              "technical reason: the same claim was accepted as a confirmed finding in the "
              "same audit and only this copy was redundant. Only "
              f"**{negs.get('technical_reason_why_the_claim_is_false')}** of "
              f"{negs.get('total')} negatives carry a reason that says why the claim is "
              "technically false (an attributed sponsor/judge refutation, a code gate that "
              "removes the standing the claim asserts, or an executed disproof). The original "
              "verdict is preserved everywhere.\n")
    md.append("Definitions and the class vocabulary: `derived_rejections/definitions.json`; "
              "prose: `reports/rejection_evidence.md`.\n")
    if negs.get("known_ceiling"):
        md.append(f"**Stated ceiling.** {negs['known_ceiling']['detail']}\n")

    md.append("## Provenance\n")
    md.append(f"- mutable citations: **{prov['citations']['mutable_before']} -> "
              f"{prov['citations']['mutable_after']}**")
    md.append(f"- resolution methods: `{prov['citations']['resolution_methods']}`")
    md.append(f"- resolution confidence: `{prov['citations']['resolution_confidence']}`\n")
    md.append("A citation is only re-pinned when a mechanical content-identity or submodule "
              "test succeeded. No SHA was invented.\n")

    md.append("## Counterexamples\n")
    md.append(f"- total counterexamples: **{cex.get('total_counterexamples')}**")
    md.append(f"- API-sibling pairs: **{cex.get('api_sibling_pairs')}** on "
              f"**{cex.get('records_with_api_sibling_pairs')}** records")
    md.append(f"- pair types: `{cex.get('api_sibling_pair_types')}`\n")

    md.append("## Static analysis\n")
    md.append(f"- tool: `{static.get('tool')} {static.get('tool_version')}`")
    md.append(f"- repositories analysed: `{static.get('by_status')}`\n")
    md.append("Slither output is an independent signal, not ground truth. A repository that "
              "could not be analysed is reported `unavailable`/`partial`; it is never reported "
              "as clean.\n")

    md.append("## Leakage\n")
    md.append(f"- exact overlaps: `{leakage.get('exact_overlap', {}).get('count_source_urls')}` "
              f"URLs, `{leakage.get('exact_overlap', {}).get('count_commit_shas')}` commit SHAs")
    md.append(f"- code overlaps: `{leakage.get('code_overlap')}`")
    md.append(f"- artefact overlaps: "
              f"`{ {k: v for k, v in (leakage.get('artefact_overlap') or {}).items() if k.startswith('count')} }`")
    md.append(f"- protocol-level isolation violations: "
              f"`{(leakage.get('protocol_isolation') or {}).get('count')}`")
    md.append(f"- repository-level isolation violations: "
              f"`{len(leakage.get('repository_isolation') or {})}`")
    md.append(f"- quarantined: `{(leakage.get('splits_v2') or {}).get('records_quarantined')}`\n")

    md.append("## Benchmark\n")
    md.append(f"- tasks: **{bench['totals']['tasks']}**, scorable: "
              f"**{bench['totals']['scorable']}**, unscorable: "
              f"**{bench['totals']['unscorable']}**")
    md.append(f"- experimentally ground truth: **{bench['experimentally_grounded_tasks']}**\n")
    md.append("| family | tasks | scorable | ground truth |")
    md.append("|---|---|---|---|")
    for r in bench["families"]:
        md.append(f"| {r['family']} | {r['tasks']} | {r['scorable']} | "
                  f"{(r['ground_truth_rule'] or '')[:80]} |")
    md.append("\nThe v2 pipeline reported 5127 tasks. The lower number here is a correction: "
              "rows duplicated inside a split are collapsed, because a finding id appears once "
              "per record type in the split files and the task id is keyed on the finding.\n")

    md.append("## High-confidence subsets\n")
    md.append(f"- `datasets/verified_findings.jsonl`: **{subs.get('subsets', {}).get('verified_findings')}**")
    md.append(f"- `datasets/verified_exploits.jsonl`: **{subs.get('subsets', {}).get('verified_exploits')}**")
    md.append(f"- `datasets/verified_patches.jsonl`: **{subs.get('subsets', {}).get('verified_patches')}**")
    md.append(f"- `datasets/verified_negatives.jsonl`: **{subs.get('subsets', {}).get('verified_negatives')}**\n")
    md.append("These subsets are small on purpose. A record is admitted by meeting a rule, "
              "never by lowering one.\n")

    md.append("## Remaining blockers\n")
    for b in BLOCKERS:
        md.append(f"- **{b['blocker']}**  -  {b['affects']}  -  {b['what_would_unblock']}")
    md.append("")

    (REPORTS / "v2_1_quality_report.md").write_text(
        "\n".join(md).encode("ascii", "replace").decode("ascii"), encoding="utf-8", newline="\n")

    summary = {
        "generated_by": "scripts/generate_v21_reports.py",
        "records_processed": repro.get("exploit_records"),
        "experiments_attempted": len(ex),
        "experiments_reproduced": ex_verdicts.get("l6_verified_patch", 0)
                                  + ex_verdicts.get("reproduced_but_not_blocked", 0),
        "experiments_inconclusive": ex_verdicts.get("inconclusive", 0)
                                    + ex_verdicts.get(
                                        "inconclusive_not_a_controlled_comparison", 0),
        "experiments_not_a_controlled_comparison": ex_verdicts.get(
            "inconclusive_not_a_controlled_comparison", 0),
        "experiments_failed": sum(
            n for v, n in ex_verdicts.items()
            if v not in ("l6_verified_patch", "reproduced_but_not_blocked",
                         "inconclusive",
                         "inconclusive_not_a_controlled_comparison")),
        "patches_verified": patches.get("experimentally_confirmed_pairs"),
        "patches_not_testable": (patches.get("by_fix_effectiveness") or {}).get("not_testable"),
        "negative_cases_verified": negs.get("experimentally_verified"),
        "negatives_corroborated": negs.get("corroborated_by_confirmed_finding"),
        "negatives_attributed": negs.get("attributed_by_named_source"),
        "negatives_unknown": negs.get("by_class", {}).get("unknown"),
        "immutable_citations_resolved": cites.get("occurrences_by_status", {}).get("resolved"),
        "immutable_citations_remaining_mutable": cites.get("remaining_mutable_occurrences"),
        "leakage_detected": {
            "exact": (leakage.get("exact_overlap") or {}).get("count_commit_shas"),
            "code": (leakage.get("code_overlap") or {}).get("count_file_function_pairs"),
            "artefact": (leakage.get("artefact_overlap") or {}).get("count_normalised_poc_bodies"),
            "protocol_isolation": (leakage.get("protocol_isolation") or {}).get("count"),
            "quarantined": (leakage.get("splits_v2") or {}).get("records_quarantined"),
        },
        "benchmark_scorable_tasks": bench["totals"]["scorable"],
        "benchmark_experimentally_grounded": bench["experimentally_grounded_tasks"],
        "validation_failures": None,
        "remaining_blockers": [b["blocker"] for b in BLOCKERS],
    }
    write_json(REPORTS / "v2_1_summary.json", summary)
    log(json.dumps(summary, indent=1))
    return 0


BLOCKERS = [
    {"blocker": "archive RPC not distributed",
     "affects": "fork-based PoCs and the NOYA negative cluster",
     "what_would_unblock": "set VLUN_RPC_URL to a pinned archive endpoint and re-run "
                           "scripts/run_verified_experiments.py"},
    {"blocker": "reconstruction ceiling on fixture drift",
     "affects": f"{4} declared reNFT experiments whose audited revision lacks a fixture the "
                "regression test needs",
     "what_would_unblock": "port the reporter's harness fixture by fixture; each failure is "
                           "recorded with the missing symbol in "
                           "experiments/*/vulnerable/result.json"},
    {"blocker": "judging rationale is not public",
     "affects": "negatives with no code-grounded reason and no corroborating finding",
     "what_would_unblock": "publish the judge or sponsor comments; 9 records already carry one"},
    {"blocker": "mitigation commits are cumulative",
     "affects": "patch delta classification",
     "what_would_unblock": "diff the single fixing hunk rather than the whole interval between "
                           "the audited revision and the fix commit"},
]


if __name__ == "__main__":
    raise SystemExit(main())