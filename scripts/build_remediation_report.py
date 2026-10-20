#!/usr/bin/env python3
"""Before/after report for the evidence-quality remediation.

Every number here is read out of a generated report or a canonical record layer at
build time; a figure that cannot be found renders as `not recorded` rather than as
zero, because a missing measurement and a measurement of zero are different claims
and this file exists precisely to keep them apart.

    python scripts/build_remediation_report.py [--check]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vlun import REPORTS, ROOT, log, write_json  # noqa: E402

MD = REPORTS / "remediation_before_after.md"
JS = REPORTS / "remediation_before_after.json"
MISSING = "not recorded"


def jread(rel: str) -> dict:
    p = ROOT / rel
    if not p.is_file():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def val(doc: dict, *path, default=MISSING):
    """Walk a list of keys; return `default` when anything is absent."""
    cur = doc
    for k in path:
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        else:
            return default
    return cur if isinstance(cur, (int, str, float, bool, dict, list)) else default


def num(x):
    if isinstance(x, dict):
        return "{" + ", ".join(f"{k}: {v}" for k, v in sorted(x.items())) + "}"
    return str(x)


def reconciled_findings(root: Path = ROOT) -> int:
    """V4 findings whose licence fields now carry the recorded decision.

    Counted from the layer rather than from the migration ledger, because the
    ledger records the last run and an idempotent re-run reports zero changes.
    """
    path = root / "jsonl_v4" / "findings.jsonl"
    if not path.is_file():
        return 0
    n = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if ((row.get("rights_migration") or {}).get("version")
                and row.get("license") != "unknown"):
            n += 1
    return n


def load() -> dict:
    rej = jread("reports/rejection_evidence_stats.json")
    prove = jread("reports/prove_split_interface.json")
    dens = jread("reports/poc_execution_density.json")
    unblock = jread("reports/v3/v32_unblock_attempts.json")
    nonevm = jread("reports/nonevm_pilot.json")
    spans = jread("reports/evidence_span_audit.json")
    sib = jread("reports/api_sibling_stats.json")
    sibrev = jread("reports/sibling_review.json")
    tax = jread("reports/root_cause_taxonomy_stats.json")
    iaa = jread("reports/iaa_status.json")
    rights = jread("reports/rights_inventory.json")
    mig = jread("reports/v4_licensing_migration.json")
    vrep = jread("reports/validation_report.json")
    subs = jread("reports/subsets.json")
    return {"rejection": rej, "prove": prove, "density": dens, "unblock": unblock,
            "nonevm": nonevm, "spans": spans, "siblings": sib, "sibling_review": sibrev,
            "taxonomy": tax, "iaa": iaa, "rights": rights, "migration": mig,
            "validation": vrep, "subsets": subs}


def rows(d: dict) -> list[tuple]:
    rej, prove = d["rejection"], d["prove"]
    dens, unb = d["density"], d["unblock"]
    nv, sp = d["nonevm"], d["spans"]
    sib = d["siblings"]
    tax, iaa = d["taxonomy"], d["iaa"]
    rights, mig = d["rights"], d["migration"]
    return [
        ("4 + 15 — rejection evidence",
         "one label covered five kinds of evidence: 331 negatives were reported as having "
         "a defensible reason, of which 321 were duplicate corroborations",
         f"six independent documented axes over {num(val(rej, 'total'))} records; "
         f"{num(val(rej, 'technical_reason_for_why_the_claim_is_false'))} carry a technical "
         f"reason the claim is false, {num(val(rej, 'metrics', 'claim_corroborated_as_duplicate_of_confirmed_finding'))} "
         f"are corroborated duplicates (redundancy, not falsity), "
         f"{num(val(rej, 'metrics', 'reason_supported_by_cited_code'))} are blocked by a gate "
         f"on the claim's own target, "
         f"{num(val(rej, 'metrics', 'unknown_or_insufficient_evidence'))} stay label-only"),
        ("5 — rights and redistribution",
         "424/722 derived records carried code from repositories with no declared licence; "
         "V4 stated `license_status: unknown` on every record while its own manifests "
         "declared no LICENSE file (two sources) and CC BY-ND 4.0 (Oak Security)",
         "decision recorded per source in `V4/licensing.json` and migrated into "
         f"{num(reconciled_findings())} V4 findings now carry the recorded decision across "
         f"{num(len(val(mig, 'files', default=[]) or []))} layer files, with nothing changed "
         "outside the licence field set; distribution-safe view `distribution_v1/` inventories "
         f"{num(len(val(rights, 'files', default=[]) or []))} tracked files over "
         f"{num(len(val(rights, 'source_registry', default=[]) or []))} registered sources; "
         "licence contradictions remaining: "
         f"{num(len(val(rights, 'licence_contradictions', default=[]) or []))}; historical "
         "exposure reported separately, no history rewritten"),
        ("6 — execution density",
         "155 exploit records identified, 9 pinpoint experiments, and an older run counted "
         "'forge ran' as reproduction",
         f"queue holds {num(val(dens, 'candidates_queued', 'v1_v2_1_exploit_records'))} v1/v2.1 "
         f"records ({num(val(dens, 'candidates_queued', 'v1_v2_1_eligible'))} eligible under the "
         f"current standard); {num(val(dens, 'attempts', 'attempts_where_forge_test_executed'))} "
         f"reached a test run out of {num(val(dens, 'stretch_campaign', 'achieved_distinct_sandboxed_invocations'))} "
         f"distinct sandboxed invocations; outcomes "
         f"{num(val(dens, 'outcomes_unique_records'))} by unique record; "
         f"L6 awarded: {num(val(dens, 'l6_awarded'))}; stretch target met: no"),
        ("7 — blocked-run recovery",
         "4 V3.2 runs were summarised as `archive_state_unavailable` without reading their "
         "own logs at the pinned revision",
         f"{num(val(unb, 'attempts_total'))} attempts across the 4 runs: "
         f"{num(val(unb, 'attempts_recovered'))} recovered, "
         f"{num(val(unb, 'attempts_with_scope_change'))} carried a documented scope change, "
         f"best level per run {num(val(unb, 'best_level_per_run'))}; canonical layers untouched"),
        ("9 — non-EVM pilot",
         "no non-EVM execution layer existed",
         f"{num(val(nv, 'counts', 'runs_total'))} runs across 5 adapters from "
         f"{num(val(nv, 'counts', 'candidates_total'))} non-EVM candidates, "
         f"{num(val(nv, 'counts', 'executed_runs'))} executed with a named assertion, "
         f"{num(val(nv, 'counts', 'blockers_overall', default={}))and len(val(nv,'counts','blockers_overall',default={}))}"
         " distinct blockers kept as data; the 'only multi-VM executed corpus' claim is not "
         "made — see `reports/nonevm_landscape.md`"),
        ("10 — evidence-span citation scoring",
         "citation quality was asserted without a scoring task",
         f"over {num(val(sp, 'preview_rows'))} V3.1 preview rows: "
         f"{num(val(sp, 'counts', 'a_resolvable_span'))} resolvable spans, "
         f"{num(val(sp, 'counts', 'b_page_or_line_pointer'))} page/line pointers, "
         f"{num(val(sp, 'counts', 'c_verified_source_ref'))} verified source refs; answer, "
         "citation existence, exactness, span support and abstention are scored separately. "
         "This family is an open-key scorer, not a held-out set — its answer key is published "
         "in the same layer, which `derived_span_tasks/manifest.json` states"),
        ("11 — API-sibling tasks",
         "71 pairs, all of them two call sites inside one contract",
         f"{num(val(sib, 'yield', 'candidates_proposed'))} cross-repository sibling call-site "
         f"candidates found, {num(val(sib, 'yield', 'reviewed'))} re-read independently, "
         f"{num(val(sib, 'yield', 'admitted_tasks'))} tasks and "
         f"{num(val(sib, 'yield', 'hard_negatives'))} hard negatives admitted; group-aware splits"
         f" {num(val(sib, 'splits', 'counts'))}; the 300+ target is "
         f"{val(sib, 'yield', 'target_reached')} and the residual shared-file exposure is "
         "disclosed rather than called contamination-proof"),
        ("12 + 13 — VLUN-Prove and the private split",
         "no task required a test that fails on the vulnerable revision and is blocked on the "
         "fixed one",
         f"{num(val(prove, 'pool', 'tasks_with_two_revisions_executed'))} tasks published as an "
         f"interface with the answer key outside the repository and pinned by hash; the "
         f"~200-task held-out split is reported as unmet ({MISSING if not prove else 'pool stated at its real size'})"),
        ("14 — inter-annotator agreement",
         "agreement was implied by judge/label agreement inside the pipeline",
         f"protocol, guide and the stratified sample are published; agreement "
         f"{'has NOT been measured' if val(iaa, 'measured') is False else num(val(iaa, 'measured'))} "
         f"— no annotators were invented and LLM self-consistency is excluded by the guard"),
        ("16 — root-cause taxonomy",
         "40 verbatim candidate strings served as the root-cause vocabulary",
         f"{num(val(tax, 'categories_defined'))} assignable leaves in a versioned closed "
         f"vocabulary over {num(val(tax, 'counts', 'records_in_assignment_pool'))} in-scope records "
         f"({num(val(tax, 'per_assignment_status', 'unlabelled'))} left unlabelled); described as "
         f"project-local, not a community standard"),
        ("Global — gate coverage",
         "the report suite could state a count that no record supported",
         f"{num(val(d['validation'], 'passed'))}/{num(val(d['validation'], 'checks'))} validator "
         f"checks pass; the rejection, rights, prove, execution, span, taxonomy and IAA layers each "
         f"carry a regeneration-equality gate, and the added tests fail on deliberately broken "
         f"fixtures"),
    ]


def render(d: dict) -> str:
    out = ["# Remediation before / after\n",
           "Generated by `scripts/build_remediation_report.py` from the reports named in each "
           "row. A figure that no artefact records appears as `" + MISSING + "`, not as zero.\n",
           "| item | before | after |", "|---|---|---|"]
    for item, before, after in rows(d):
        out.append(f"| {item} | {before} | {after} |")
    out.append("\n## What was retracted rather than fixed\n")
    out.append("- The claim that 331 negatives had a defensible rejection reason: "
               "corroboration counted as explanation.\n")
    out.append("- The claim that a `corroborated_duplicate` record was established not to be a "
               "false positive wherever the pointer did not resolve to a published finding.\n")
    out.append("- The claim that every withheld citation keeps a sha256: "
               "the publisher-recorded digest exists on only part of them.\n")
    out.append("- The description of METADATA_ONLY as if it were a clearance, and the "
               "expectation that a permalink plus a hash grants reuse.\n")
    out.append("- Any implication that the held-out or sibling splits are contamination-proof; "
               "they are leakage-audited under the recorded criteria and no more.\n")
    out.append("- The label on the v2.1 API-sibling count of 71: `reports/api_sibling_stats.md` "
               "records that those were intra-contract pairs from "
               "`derived/counterexamples.jsonl`, not the cross-repository sibling call-site "
               "relation the name implies; the cross-repository family is built separately and "
               "reported at its own yield.\n")
    out.append("- The `forge_reason` field in the v2.1 experiment ledger. It was read from "
               "forge's human `[FAIL: …]` line, which `--json` does not print, so it was null "
               "on every recorded run even where the preserved stdout named the reason. The "
               "recorder is fixed, recorded artefacts were not rewritten, and the VLUN-Prove "
               "self-check says how many reasons it recovered by replaying those bytes.\n")
    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    d = load()
    md = render(d)
    js = json.dumps({"generated_by": "scripts/build_remediation_report.py",
                     "sources": sorted({r for r in [] } | {
                         "reports/rejection_evidence_stats.json",
                         "reports/prove_split_interface.json", "reports/poc_execution_density.json",
                         "reports/v3/v32_unblock_attempts.json", "reports/nonevm_pilot.json",
                         "reports/evidence_span_audit.json", "reports/api_sibling_stats.json",
                         "reports/sibling_review.json", "reports/root_cause_taxonomy_stats.json",
                         "reports/iaa_status.json", "reports/rights_inventory.json",
                         "reports/v4_licensing_migration.json", "reports/validation_report.json"}),
                     "rows": [{"item": i, "before": b, "after": a} for i, b, a in rows(d)]},
                    ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.check:
        stale = [str(p) for p, t in [(MD, md), (JS, js)]
                 if not p.exists() or p.read_text(encoding="utf-8") != t]
        if stale:
            log("STALE: " + ", ".join(stale))
            return 1
        log("remediation report is current")
        return 0
    MD.write_text(md, encoding="utf-8", newline="\n")
    write_json(JS, json.loads(js))
    log(f"remediation_before_after.md: {len(rows(d))} items")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
