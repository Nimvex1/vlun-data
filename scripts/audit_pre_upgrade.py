#!/usr/bin/env python3
"""Produce reports/pre_upgrade_audit.json.

This runs against the *original* `jsonl/` evidence layer and the v1 statistics
snapshot kept at reports/legacy/dataset_stats_v1_reported.json. It answers:
what is actually in the repository, where does the published reporting disagree
with it, and what is missing.

    python scripts/audit_pre_upgrade.py

Deterministic: same inputs -> same report. It reads README.md and mechanically
checks every numeric claim it can extract, so the "documentation lies about the
data" section is evidence, not opinion.
"""

from __future__ import annotations

import collections
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vlun import (  # noqa: E402
    JSONL, REPORTS, ROOT, code_entries, load_core, load_splits, log, rec_id,
    run, snippet_entries, write_json,
)

LEGACY_STATS = REPORTS / "legacy" / "dataset_stats_v1_reported.json"
README = ROOT / "README.md"
MANIFEST = ROOT / "publish_manifest.json"

# v1 flat key -> (canonical computed value, what the key was supposed to mean)
_V1_RECHECK = {
    "total_findings": lambda s: s["findings"]["total"],
    "confirmed_findings": lambda s: s["findings"]["confirmed"],
    "negative_findings": lambda s: s["negatives"]["total"],
    "duplicates": lambda s: s["negatives"]["by_validation_status"].get("duplicate", 0),
    "high": lambda s: s["findings"]["by_severity"].get("high", 0),
    "medium": lambda s: s["findings"]["by_severity"].get("medium", 0),
    "low": lambda s: s["findings"]["by_severity"].get("low", 0),
    "qa": lambda s: s["findings"]["by_severity"].get("qa", 0),
    "judged_findings": lambda s: s["findings"]["judged_higher_than_qa"],
    "qa_findings": lambda s: s["findings"]["qa_records"],
    "poc_available": lambda s: s["field_coverage"]["poc_available_true"],
    "patch_available": lambda s: s["field_coverage"]["patch_available_true"],
    "invariant_records": lambda s: s["field_coverage"]["findings_with_invariant"],
    "exploit_records": lambda s: s["exploits"]["records"],
    "patch_records": lambda s: s["patches"]["records"],
    "protocol_records": lambda s: s["protocol_records"]["total"],
    "metadata_records": lambda s: s["metadata_records"]["total"],
    "error_records": lambda s: s["error_records"]["total"],
    "unique_protocols": lambda s: s["protocol_records"]["total"],
    "unique_vulnerability_classes": lambda s: s["taxonomy"]["distinct_classes"],
    "unique_vulnerability_categories": lambda s: s["taxonomy"]["distinct_top_level_categories"],
    "negatives_with_public_reasoning": lambda s: s["negatives"]["by_rejection_basis"].get("public_judge_or_sponsor_comment", 0),
    "negatives_with_public_discussion_only": lambda s: s["negatives"]["by_rejection_basis"].get("public_discussion_no_verdict_attributed", 0),
    "negatives_with_label_only_rejection": lambda s: s["negatives"]["by_rejection_basis"].get("label_only", 0),
    "code_context_entries": lambda s: s["code_context"]["entries_redistributed"],
    "code_context_with_verified_line_range": lambda s: s["code_context"]["redistributed_line_range_verified"],
    "findings_with_attacker_capabilities": lambda s: sum(
        1 for _ in ()) or None,  # filled below
    "findings_with_attacker_limitations": lambda s: None,
    "findings_with_attack_path": lambda s: None,
    "findings_with_stated_impact": lambda s: None,
    "findings_with_named_judge_or_sponsor_verdict": lambda s: None,
    "judge_severity_changes": lambda s: None,
}


def _recompute_findings_level(core):
    findings, negatives = core["findings"], core["negatives"]
    judged = findings + negatives
    def n(fn, rows): return sum(1 for r in rows if fn(r))
    return {
        "findings_with_attacker_capabilities": n(lambda r: r.get("security_reasoning", {}).get("attacker_capabilities"), findings),
        "findings_with_attacker_limitations": n(lambda r: r.get("security_reasoning", {}).get("attacker_limitations"), findings),
        "findings_with_attack_path": n(lambda r: r.get("security_reasoning", {}).get("attack_path"), findings),
        "findings_with_stated_impact": n(lambda r: any(
            (r.get("security_reasoning", {}).get("impact") or {}).get(k)
            for k in ("integrity", "financial", "protocol_state", "availability", "confidentiality")), findings),
        "findings_with_named_judge_or_sponsor_verdict": n(lambda r: r.get("provenance", {}).get("judge_and_sponsor_quotes"), findings),
        "judge_severity_changes": n(lambda r: (r.get("validation") or {}).get("severity_change"), findings),
    }


README_CLAIMS = [
    # (regex, description, canonical computed value, how to compare)
    (r"`?negative_findings\.jsonl`?\s+(\d+) records", "layout: negative_findings.jsonl records", lambda s, c: s["negatives"]["total"], "equal"),
    (r"`?findings\.jsonl`?\s+(\d+) records", "layout: findings.jsonl records", lambda s, c: s["findings"]["total"], "equal"),
    (r"`?exploits\.jsonl`?\s+(\d+) records", "layout: exploits.jsonl records", lambda s, c: s["exploits"]["records"], "equal"),
    (r"`?patches\.jsonl`?\s+(\d+) records", "layout: patches.jsonl records", lambda s, c: s["patches"]["records"], "equal"),
    (r"`?protocol\.jsonl`?\s+(\d+) records", "layout: protocol.jsonl records", lambda s, c: s["protocol_records"]["total"], "equal"),
    (r"`?metadata\.jsonl`?\s+(\d+) records", "layout: metadata.jsonl records", lambda s, c: s["metadata_records"]["total"], "equal"),
    (r"`?errors\.jsonl`?\s+(\d+) records", "layout: errors.jsonl records", lambda s, c: s["error_records"]["total"], "equal"),
    (r"(\d+) of 458 negative findings have only a label",
     "limitation 3: negatives rejected on a label alone", lambda s, c: s["negatives"]["by_rejection_basis"].get("label_only", 0), "equal"),
    (r"(\d+) of 264 records carry an invariant",
     "limitation 7: findings carrying an invariant", lambda s, c: s["field_coverage"]["findings_with_invariant"], "equal"),
    (r"(\d+) repositories declare no licence",
     "limitation 5: repositories with no declared licence",
     lambda s, c: len({r["source"]["repository"] for rows in (c["findings"], c["negatives"]) for r in rows
                       if not (r.get("provenance", {}).get("license") or "").strip()}), "equal"),
    (r"(\d+) of 740 permalinks could not be used as source",
     "limitation 4: permalinks unusable as a source (findings scope)",
     lambda s, c: sum(1 for r in c["findings"] for e in (list(r.get("code_context") or []) + list(r.get("vulnerable_code") or []))
                       if not e.get("line_range_verified")), "scope_changed"),
    (r"re-checks all\s+([\d,]+) verified ranges",
     "limitation 4: line ranges re-verified byte-for-byte",
     lambda s, c: s["code_context"]["redistributed_line_range_verified"], "scope_changed"),
]


def audit() -> dict:
    core = load_core()
    splits = load_splits()
    findings, negatives = core["findings"], core["negatives"]
    judged = findings + negatives
    fl = _recompute_findings_level(core)

    from generate_stats import build_stats
    stats = build_stats()

    out: dict = {
        "audit_of": "published v1 repository (jsonl/ + splits/ + reports/)",
        "dataset_version_in_data": sorted({r.get("dataset_version") for rows in core.values() for r in rows}),
        "how_to_reproduce": [
            "python scripts/audit_pre_upgrade.py",
            "python scripts/generate_stats.py",
        ],
    }

    # ---- 1. record counts -------------------------------------------------
    out["record_counts"] = {
        "by_file": {k: len(v) for k, v in sorted(core.items())},
        "by_split": {k: len(v) for k, v in sorted(splits.items())},
        "total_jsonl_records": sum(len(v) for v in core.values()),
        "total_split_records": sum(len(v) for v in splits.values()),
        "finding_records_are_unique": len({rec_id(r) for r in findings}) == len(findings),
        "split_union_equals_findings_file": (
            {rec_id(r) for v in splits.values() for r in v} == {rec_id(r) for r in findings}),
        "v1_manifest_records_written": json.loads(MANIFEST.read_text(encoding="utf-8"))["records_written"]
        if MANIFEST.exists() else None,
    }

    # ---- 2. schema inventory ---------------------------------------------
    def keys_of(rows):
        c = collections.Counter()
        for r in rows:
            c.update(r.keys())
        return c

    schema = {}
    for fam, rows in sorted(core.items()):
        c = keys_of(rows)
        schema[fam] = {
            "records": len(rows),
            "top_level_keys": sorted(c),
            "always_present": sorted(k for k, v in c.items() if v == len(rows)),
            "sometimes_present": sorted(k for k, v in c.items() if v < len(rows)),
        }
    out["schema_inventory"] = schema
    nested = {}
    for block in ("finding", "security_reasoning", "poc", "patch", "validation", "provenance", "negative_analysis"):
        c = collections.Counter()
        for r in judged:
            if isinstance(r.get(block), dict):
                c.update(r[block].keys())
        nested[block] = sorted(c)
    out["schema_inventory"]["_nested_blocks_over_judged_records"] = nested
    out["schema_inventory"]["_v2_fields_absent_from_v1"] = [
        k for k in ("evidence", "security_state_transition", "attacker_model",
                    "quality", "taxonomy", "verification", "benchmark_tasks")
        if not any(k in r for rows in core.values() for r in rows)
    ]

    # ---- 3. missing / empty fields ---------------------------------------
    emptiness = collections.Counter()
    for r in judged:
        for k, v in r.items():
            if v in ("", [], {}, None):
                emptiness[k] += 1
    out["missing_fields"] = {
        "empty_or_null_top_level_field_counts": dict(emptiness.most_common()),
        "records_with_empty_finding_summary": sum(1 for r in findings if not (r["finding"].get("summary") or "").strip()),
        "records_with_empty_finding_root_cause": sum(1 for r in findings if not (r["finding"].get("root_cause") or "").strip()),
        "records_with_no_code_context_and_no_reference": sum(
            1 for r in judged if not code_entries(r)),
        "records_with_no_provenance_url": sum(
            1 for r in judged if not (r.get("provenance", {}).get("source_urls"))),
        "records_with_undeclared_licence": sum(
            1 for r in judged if not (r.get("provenance", {}).get("license") or "").strip()),
        "note": "v1 has no per-field evidence type: every populated field reads as equally trustworthy.",
    }

    # ---- 4. validation weaknesses (what v1 does NOT check) ---------------
    out["validation_weaknesses"] = [
        {"id": "V1", "gap": "no machine-readable gate exists in the published repo",
         "detail": "README references scripts/build_all.py and scripts/validate.py, but no scripts/ "
                   "directory is published. The gate is described, not runnable."},
        {"id": "V2", "gap": "reported statistics were never recomputed",
         "detail": "reports/dataset_stats.json is a hand-maintained artefact; see statistics_inconsistencies."},
        {"id": "V3", "gap": "README numbers are not generated from the data",
         "detail": "see documentation_inconsistencies; several figures describe the pre-redaction build."},
        {"id": "V4", "gap": "no leakage measurement beyond three hard checks",
         "detail": "v1 checks repo-in-two-splits, id-in-two-splits, file::function-in-two-splits. "
                   "No code, semantic or near-duplicate similarity detection."},
        {"id": "V5", "gap": "PoC metadata cannot be checked because nothing was executed",
         "detail": "every poc.reproducible is false, so there is no invariant tying a PoC to a run."},
        {"id": "V6", "gap": "no record-level uniqueness key",
         "detail": "findings are keyed by source.repository + finding.id only; exploit/patch/protocol "
                   "rows carry no primary key field, so dedup depends on positional conventions."},
        {"id": "V7", "gap": "severity consistency across files is unchecked",
         "detail": "findings.jsonl, exploits.jsonl and splits/*.jsonl each restate severity; no "
                   "cross-file agreement rule exists."},
    ]

    # ---- 5. provenance weaknesses ----------------------------------------
    permalinks = [u for r in judged for u in (r.get("provenance", {}).get("source_urls") or []) if "/blob/" in u]
    bad_sha = [u for u in permalinks if not re.search(r"/blob/[0-9a-f]{40}/", u)]
    out["provenance_weaknesses"] = {
        "blob_permalinks": len(permalinks),
        "blob_permalinks_without_40hex_commit": bad_sha[:10],
        "records_with_zero_permalinks": sum(1 for r in judged if not any("/blob/" in u for u in (r.get("provenance", {}).get("source_urls") or []))),
        "per_field_evidence_type": "absent — v1 documents *where* a field came from in README prose, "
                                   "not in the record, so a consumer cannot tell a quote from a derivation",
        "no_distinction_between": [
            "observed in source vs stated by the report vs inferred by the rule-based classifier",
            "judge verdict vs sponsor opinion vs dataset-builder judgement",
            "attacker capability read off code vs attacker capability asserted in prose",
        ],
        "classifier_evidence_present_on": sum(1 for r in judged if r.get("classifier_evidence")),
        "classifier_evidence_absent_on": sum(1 for r in judged if not r.get("classifier_evidence")),
        "invariants_with_source_type": sum(1 for r in judged for iv in (r.get("security_reasoning", {}).get("invariants") or []) if isinstance(iv, dict) and iv.get("source_type")),
        "invariant_source_record_level_values": dict(collections.Counter(
            (r.get("security_reasoning", {}).get("invariant_source") or "<missing>") for r in judged)),
    }

    # ---- 6. leakage risks -------------------------------------------------
    def norm_text(s: str) -> str:
        return re.sub(r"[^a-z0-9]+", " ", (s or "").lower()).strip()

    split_of = {rec_id(r): name for name, rows in splits.items() for r in rows}
    repo_split = collections.defaultdict(set)
    for name, rows in splits.items():
        for r in rows:
            repo_split[r["source"]["repository"]].add(name)
    id_sets = {name: {rec_id(r) for r in rows} for name, rows in splits.items()}
    ff_sets = {}
    for name, rows in splits.items():
        ff_sets[name] = {f"{e.get('file')}::{e.get('function')}" for r in rows for e in code_entries(r) if e.get("file")}
    all_ff = collections.defaultdict(set)
    for name, s in ff_sets.items():
        for k in s:
            all_ff[k].add(name)

    def pairs(sets):
        names = sorted(sets)
        return {f"{a}|{b}": len(sets[a] & sets[b]) for i, a in enumerate(names) for b in names[i + 1:]}

    # within-split near-duplicate detection (exact id / file::function reuse)
    dup_in_split = {}
    for name, rows in splits.items():
        c = collections.Counter(rec_id(r) for r in rows)
        d = {k: v for k, v in c.items() if v > 1}
        if d:
            dup_in_split[name] = d

    out["leakage_risks"] = {
        "repositories_in_multiple_splits": {k: sorted(v) for k, v in repo_split.items() if len(v) > 1},
        "finding_ids_in_multiple_splits": {k: v for k, v in pairs(id_sets).items() if v},
        "file_function_pairs_in_multiple_splits_count": sum(v for v in pairs(ff_sets).values()),
        "file_function_pairs_in_multiple_splits_top": dict(sorted(
            {k: v for k, v in all_ff.items() if len(v) > 1}.items(),
            key=lambda kv: (-len(kv[1]), kv[0]))[:15]),
        "duplicate_ids_inside_a_single_split": dup_in_split,
        "same_repository_source_across_exploit_patch_rows": sorted({
            r["source"]["repository"] for fam in ("exploits", "patches")
            for r in core[fam]} & set(repo_split)),
        "unmeasured_in_v1": [
            "identical or normalised code snippets shared across splits",
            "function-signature collisions across splits",
            "semantic near-duplicates (same root cause, different wording)",
            "duplicate submissions inside the negative corpus that share a canonical target",
        ],
    }

    # ---- 7. executable PoC coverage --------------------------------------
    ex = core["exploits"]
    poc_repro = sum(1 for r in judged if r.get("poc", {}).get("reproducible"))
    out["executable_poc_coverage"] = {
        "exploit_records": len(ex),
        "records_with_poc_available_flag": stats["field_coverage"]["poc_available_true"],
        "poc_code_present": stats["field_coverage"]["poc_available_true"] - sum(
            1 for r in judged if r.get("poc", {}).get("available") and not (r["poc"].get("code") or "").strip()),
        "poc_flagged_reproducible": poc_repro,
        "poc_compiled": 0,
        "poc_executed": 0,
        "exploit_impact_confirmed_by_execution": 0,
        "poc_framework_declared": stats["exploits"]["framework_declared"],
        "poc_target_file_declared": sum(1 for r in ex if (r["exploit"].get("test_file") or "").strip()),
        "poc_test_name_declared": sum(1 for r in ex if (r["exploit"].get("test_name") or "").strip()),
        "reproducibility_note_variants": dict(collections.Counter(
            (r["exploit"].get("reproducibility_note") or "")[:60] for r in ex)),
        "compiler_or_toolchain_pinned_per_record": False,
        "execution_evidence_fields_present": False,
        "conclusion": "PoC material exists as quoted text only. Nothing in v1 was compiled or run, "
                      "so 'available' cannot be distinguished from 'works'.",
    }

    # ---- 8. code context coverage ----------------------------------------
    out["code_context_coverage"] = {
        **stats["code_context"],
        "records_with_redistributed_snippet": sum(1 for r in judged if snippet_entries(r)),
        "records_reference_only_only": stats["code_context"]["records_with_reference_only_only"],
        "records_with_no_code_at_all": out["missing_fields"]["records_with_no_code_context_and_no_reference"],
        "withheld_note_kind": dict(collections.Counter(
            (r.get("code_reference_only_note") or "")[:40] for r in judged if r.get("code_reference_only"))),
        "no_enclosing_contract_or_caller_callee_layer": True,
        "context_is_flat_list_of_permalinks_not_a_dependency_graph": True,
    }

    # ---- 9. negative-example quality -------------------------------------
    na = [r.get("negative_analysis", {}) for r in negatives]
    out["negative_example_quality"] = {
        "total": len(negatives),
        "by_rejection_basis": stats["negatives"]["by_rejection_basis"],
        "label_only": sum(1 for x in na if x.get("rejection_basis") == "label_only"),
        "with_nonempty_why_it_looked_plausible": sum(1 for x in na if (x.get("why_it_looked_plausible") or "").strip()),
        "with_nonempty_why_it_is_not_a_vulnerability": sum(1 for x in na if (x.get("why_it_is_not_a_vulnerability") or "").strip()),
        "with_code_available_to_explain_the_rejection": sum(1 for r in negatives if snippet_entries(r)),
        "label_only_with_code_available": sum(
            1 for r in negatives if r.get("negative_analysis", {}).get("rejection_basis") == "label_only" and snippet_entries(r)),
        "label_only_without_code": sum(
            1 for r in negatives if r.get("negative_analysis", {}).get("rejection_basis") == "label_only" and not snippet_entries(r)),
        "structured_fields_present": sorted(na[0].keys()) if na else [],
        "missing_structured_fields": [f for f in (
            "candidate_claim", "relevant_code", "blocking_condition", "why_exploit_fails",
            "verdict", "evidence") if f not in (na[0] if na else {})],
        "carry_severity_at_all": stats["negatives"]["carrying_severity"],
        "duplicates_pointing_at_canonical": sum(1 for r in negatives if (r.get("validation") or {}).get("duplicate_of")),
        "duplicate_targets_unresolvable": sorted({
            t for r in negatives if (t := (r.get("validation") or {}).get("duplicate_of"))
            and rec_id_of_target(t, findings, negatives) is None})[:20],
        "counterexamples_for_confirmed_findings": 0,
        "verdict_attribution_collapsed_to": "finding.status / validation.status only",
    }

    # ---- 10. patch coverage ----------------------------------------------
    pa = core["patches"]
    out["patch_coverage"] = {
        **stats["patches"],
        "records_with_diff": 0,
        "records_with_regression_test": 0,
        "records_with_fix_verification": 0,
        "vulnerable_commit_present": stats["patches"]["with_vulnerable_commit"],
        "note": "patches.jsonl records the fixing PR and its merge commit, but the diff itself is "
                "withheld in this published copy and no PoC was run against vulnerable vs fixed code.",
    }

    # ---- 11. statistics inconsistencies ----------------------------------
    out["statistics_inconsistencies"] = _recheck_legacy(stats, fl)

    # ---- 12. documentation inconsistencies --------------------------------
    out["documentation_inconsistencies"] = _recheck_readme(stats, core)

    # ---- 13. recommended priorities ---------------------------------------
    out["recommended_upgrade_priorities"] = [
        {"priority": "P0", "work": "authoritative stats + validation gate",
         "why": "the published numbers disagree with the data; nothing downstream can be trusted",
         "gap_ids": out["statistics_inconsistencies"] and ["S1"] or []},
        {"priority": "P0", "work": "per-field evidence semantics",
         "why": "without it a derived sentence is indistinguishable from an executed fact"},
        {"priority": "P1", "work": "compile + run the quoted PoCs at the pinned commits",
         "why": f"{stats['exploits']['records']} PoCs are text-only; this is the single largest "
                "quality gap and it is also the only one that can falsify the dataset"},
        {"priority": "P2", "work": "hard negatives grounded in retrieved code",
         "why": f"{sum(1 for x in na if x.get('rejection_basis') == 'label_only')} negatives are label-only; "
                f"{out['negative_example_quality']['label_only_with_code_available']} of them already have "
                "code in the dataset that could ground the rejection mechanically"},
        {"priority": "P2", "work": "counterexamples for confirmed H/M",
         "why": "teaches do-not-report-bug from the same code that supports report-bug"},
        {"priority": "P3", "work": "dependency-aware context expansion at pinned commits",
         "why": "v1 context is a flat permalink list; no caller/callee/modifier/state layer"},
        {"priority": "P4", "work": "state-transition + structured attacker model",
         "why": "attack_path strings exist but carry no states, no actor capabilities, no invariants to check"},
        {"priority": "P5", "work": "patch retrieval and vulnerable-vs-fixed execution",
         "why": "'a PR exists' is not 'the fix works'"},
        {"priority": "P6", "work": "code + semantic leakage detection and a real benchmark",
         "why": "repository-level splitting alone does not prevent near-duplicate leakage"},
    ]
    return out


def rec_id_of_target(target, findings, negatives):
    """Resolve a duplicate pointer such as 'issue #136' or '2024-04-noya/M-40'."""
    t = (target or "").strip()
    ids = {rec_id(r) for r in findings} | {rec_id(r) for r in negatives}
    if t in ids:
        return t
    return None


def _recheck_legacy(stats, fl):
    problems = []
    if not LEGACY_STATS.exists():
        return [{"id": "S0", "detail": "v1 statistics snapshot not present; nothing to recheck"}]
    v1 = json.loads(LEGACY_STATS.read_text(encoding="utf-8"))
    computed = {k: fn(stats) for k, fn in _V1_RECHECK.items() if fn(stats) is not None}
    computed.update(fl)
    for key, want in sorted(computed.items()):
        got = v1.get(key)
        if got != want:
            problems.append({
                "id": f"S:{key}",
                "v1_reported": got,
                "computed_from_jsonl": want,
                "direction": "undercount" if isinstance(got, int) and isinstance(want, int) and got < want else "overcount_or_other",
            })
    # fields present in v1 with no counterpart
    unmapped = sorted(set(v1) - set(_V1_RECHECK) - {"dataset_version"})
    problems.append({
        "id": "S:unmapped_v1_keys",
        "detail": "v1 keys with no defined canonical meaning (aggregations, not verifiable facts)",
        "keys": unmapped,
    })
    return problems


def _recheck_readme(stats, core):
    """Mechanically check every numeric claim in README.md against the data."""
    if not README.exists():
        return []
    text = README.read_text(encoding="utf-8")
    out = []
    for pattern, desc, resolver, mode in README_CLAIMS:
        for m in re.finditer(pattern, text):
            claimed = int(m.group(1).replace(",", ""))
            want = resolver(stats, core)
            entry = {"claim": desc, "readme_text": m.group(0), "readme_value": claimed,
                     "computed_from_jsonl": want}
            if mode == "equal":
                entry["verdict"] = "consistent" if claimed == want else "MISMATCH"
            else:
                entry["verdict"] = "NOT_REPRODUCIBLE"
                entry["why"] = (
                    "the README figure comes from the pre-redaction internal build, whose code-context "
                    "population (740 permalinks, 1435 verified ranges) is larger than what this published "
                    "copy redistributes, so the same population cannot be recounted here. The computed "
                    "value is the closest comparable figure in this copy.")
            out.append(entry)

    # Claims with no computable counterpart in the published copy at all.
    for desc, why in [
        ("limitation 4: 'scripts/audit_line_ranges.py ... currently reports zero mismatches'",
         "no scripts/ directory is published, so the cited re-check cannot be re-run by a consumer"),
        ("Rebuilding section: scripts/build_all.py, scripts/validate.py, scripts/fetch_*.py",
         "none of these scripts are published; the documented pipeline is not runnable from this copy"),
        ("Layout section: raw/, normalized/ directories",
         "neither directory is published; the original evidence dump is not redistributable"),
    ]:
        if why.split(",")[0].split(";")[0] in text or desc.split(":")[0] in text:
            out.append({"claim": desc, "verdict": "NOT_REPRODUCIBLE", "why": why})
    return out


def main() -> int:
    report = audit()
    write_json(REPORTS / "pre_upgrade_audit.json", report)
    si = [p for p in report["statistics_inconsistencies"] if "v1_reported" in p]
    di = [p for p in report["documentation_inconsistencies"] if p.get("verdict") not in ("consistent",)]
    log(f"wrote reports/pre_upgrade_audit.json")
    log(f"  statistics inconsistencies : {len(si)}")
    for p in si:
        log(f"    - {p['id']}: v1={p['v1_reported']} computed={p['computed_from_jsonl']}")
    log(f"  documentation problems    : {len(di)}")
    for p in di:
        log(f"    - {p['claim']}: {p.get('verdict')} ({p.get('readme_value')} vs {p.get('computed_from_jsonl', '-')})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())