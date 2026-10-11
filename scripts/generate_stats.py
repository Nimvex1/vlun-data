#!/usr/bin/env python3
"""Single authoritative statistics generator.

Every number in reports/dataset_stats.json is computed here, directly from the
canonical JSONL in `jsonl/`. Nothing is hand-edited. `scripts/validate.py`
recomputes and fails the build if any reported value differs.

    python scripts/generate_stats.py            # write reports/dataset_stats.json
    python scripts/generate_stats.py --check    # exit 1 if the file is stale
    python scripts/generate_stats.py --stdout   # print JSON, write nothing

Scope note: the published repository is a *redacted* build. Source that the
audited protocol does not license for redistribution lives in
`code_reference_only` (path + commit + line range + permalink, no text). The
stats therefore report redistributed and withheld code context separately rather
than pretending coverage is uniform.
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vlun import (  # noqa: E402
    DATASET_VERSION,
    DERIVED,
    REPORTS,
    ROOT,
    code_entries,
    load_core,
    load_splits,
    log,
    rec_id,
    snippet_entries,
    write_json,
)

REPO = "code-423n4"


def _norm(s: str | None) -> str:
    return (s or "").strip().rstrip()


def _sorted_counter(c: collections.Counter) -> dict:
    return dict(sorted(c.items(), key=lambda kv: (-kv[1], str(kv[0]))))


def build_stats() -> dict:
    core = load_core()
    findings = core["findings"]
    negatives = core["negatives"]
    splits = load_splits()
    judged = findings + negatives  # every record that carries a finding block

    # --- record inventory ---------------------------------------------------
    s: dict = {
        "dataset_version": DATASET_VERSION,
        "source_layer_version": "1.0",
        "generated_by": "scripts/generate_stats.py",
        "record_counts": {k: len(v) for k, v in sorted(core.items())},
        "split_counts": {k: len(v) for k, v in sorted(splits.items())},
        "total_records_all_files": sum(len(v) for v in core.values()),
        "total_split_records": sum(len(v) for v in splits.values()),
    }

    # --- findings ----------------------------------------------------------
    sev = collections.Counter(_norm(r["finding"].get("severity")) or "<missing>" for r in findings)
    vstat = collections.Counter(_norm(r["finding"].get("status")) or "<missing>" for r in findings)
    rclass = collections.Counter(_norm(r["finding"].get("record_class")) or "<missing>" for r in findings)
    s["findings"] = {
        "total": len(findings),
        "by_severity": _sorted_counter(sev),
        "by_validation_status": _sorted_counter(vstat),
        "by_record_class": _sorted_counter(rclass),
        "by_repository": _sorted_counter(collections.Counter(r["source"]["repository"] for r in findings)),
        "judged_higher_than_qa": sum(1 for r in findings if _norm(r["finding"].get("record_class")) == "judged"),
        "qa_records": rclass.get("qa", 0),
        "confirmed": vstat.get("confirmed", 0),
        "by_confidence": _sorted_counter(collections.Counter(_norm(r.get("confidence")) for r in findings)),
    }

    # --- negatives ---------------------------------------------------------
    nstat = collections.Counter(_norm(r["finding"].get("status")) or "<missing>" for r in negatives)
    rbasis = collections.Counter(
        _norm(r.get("negative_analysis", {}).get("rejection_basis")) or "<missing>" for r in negatives
    )
    nsev = collections.Counter(_norm(r["finding"].get("severity")) or "<missing>" for r in negatives)
    s["negatives"] = {
        "total": len(negatives),
        "by_validation_status": _sorted_counter(nstat),
        "by_rejection_basis": _sorted_counter(rbasis),
        "by_repository": _sorted_counter(collections.Counter(r["source"]["repository"] for r in negatives)),
        "carrying_severity": sum(1 for r in negatives if _norm(r["finding"].get("severity"))),
        "severity_values": _sorted_counter(nsev),
        "with_verbatim_code_context": sum(1 for r in negatives if snippet_entries(r)),
        "with_reference_only_code_context": sum(1 for r in negatives if r.get("code_reference_only")),
    }

    # --- exploits ----------------------------------------------------------
    ex = core["exploits"]
    s["exploits"] = {
        "records": len(ex),
        "by_repository": _sorted_counter(collections.Counter(r["source"]["repository"] for r in ex)),
        "framework_declared": _sorted_counter(collections.Counter(_norm(r["exploit"].get("framework")) or "<undeclared>" for r in ex)),
        "with_attack_sequence": sum(1 for r in ex if r["exploit"].get("attack_sequence")),
        "with_poc_code": sum(1 for r in ex if _norm(r["exploit"].get("code"))),
        "flagged_reproducible_in_dataset": sum(1 for r in ex if r["exploit"].get("reproducible_in_dataset")),
        "by_severity": _sorted_counter(collections.Counter(_norm(r["finding"].get("severity")) or "<missing>" for r in ex)),
    }

    # --- patches -----------------------------------------------------------
    pa = core["patches"]
    s["patches"] = {
        "records": len(pa),
        "with_fix_commit": sum(1 for r in pa if _norm(r["patch"].get("fixed_commit"))),
        "with_vulnerable_commit": sum(1 for r in pa if _norm(r["patch"].get("vulnerable_commit"))),
        "with_diff_redistributed": sum(1 for r in pa if _norm(r["patch"].get("diff"))),
        "diff_withheld_by_licence": sum(1 for r in pa if r["patch"].get("diff_withheld")),
        "with_why_the_fix_works": sum(1 for r in pa if _norm(r["patch"].get("why_the_fix_works"))),
        "by_remediation_status": _sorted_counter(collections.Counter(_norm(r["patch"].get("remediation_status")) or "<missing>" for r in pa)),
        "distinct_prs": len({p for r in pa for p in (r["patch"].get("prs") or [])}),
    }

    # --- protocol / metadata / errors --------------------------------------
    s["protocol_records"] = {
        "total": len(core["protocol"]),
        "names": sorted(_norm(r["protocol"].get("name")) for r in core["protocol"]),
        "distinct_licenses": sorted({_norm(r.get("provenance", {}).get("license")) or "<undeclared>" for r in core["protocol"]}),
    }
    s["metadata_records"] = {"total": len(core["metadata"])}
    s["error_records"] = {
        "total": len(core["errors"]),
        "by_kind": _sorted_counter(collections.Counter(_norm(r["error"].get("kind")) or "<missing>" for r in core["errors"])),
        "by_repository": _sorted_counter(collections.Counter(_norm(r["source"].get("repository")) or "<global>" for r in core["errors"])),
    }

    # --- field-level coverage over every finding-shaped record -------------
    # These are the numbers v1 conflated: a `poc` *block* can be present and
    # populated on far more records than there are `exploits.jsonl` rows.
    s["field_coverage"] = {
        "judged_records_total": len(judged),
        "poc_block_present": sum(1 for r in judged if "poc" in r),
        "poc_available_true": sum(1 for r in judged if r.get("poc", {}).get("available")),
        "poc_available_true_findings": sum(1 for r in findings if r.get("poc", {}).get("available")),
        "poc_available_true_negatives": sum(1 for r in negatives if r.get("poc", {}).get("available")),
        "poc_flagged_reproducible": sum(1 for r in judged if r.get("poc", {}).get("reproducible")),
        "patch_available_true": sum(1 for r in judged if r.get("patch", {}).get("available")),
        "patch_available_true_findings": sum(1 for r in findings if r.get("patch", {}).get("available")),
        "patch_available_true_negatives": sum(1 for r in negatives if r.get("patch", {}).get("available")),
        "has_code_context_block": sum(1 for r in judged if r.get("code_context")),
        "has_attack_path": sum(1 for r in judged if r.get("security_reasoning", {}).get("attack_path")),
        "has_attacker_capabilities": sum(1 for r in judged if r.get("security_reasoning", {}).get("attacker_capabilities")),
        "has_attacker_limitations": sum(1 for r in judged if r.get("security_reasoning", {}).get("attacker_limitations")),
        "has_invariant": sum(1 for r in judged if r.get("security_reasoning", {}).get("invariants")),
        "findings_with_invariant": sum(1 for r in findings if r.get("security_reasoning", {}).get("invariants")),
        "has_stated_impact": sum(1 for r in judged if any(
            _norm(r.get("security_reasoning", {}).get("impact", {}).get(k))
            for k in ("integrity", "financial", "protocol_state", "availability", "confidentiality")
        )),
        "has_named_verdict_quote": sum(1 for r in judged if r.get("provenance", {}).get("judge_and_sponsor_quotes")),
        "has_severity_change": sum(1 for r in judged if _norm(r.get("validation", {}).get("severity_change"))),
        "license_declared": sum(1 for r in judged if _norm(r.get("provenance", {}).get("license"))),
        "license_verified": sum(1 for r in judged if r.get("provenance", {}).get("license_verified")),
    }

    # --- code context: redistributed vs withheld ---------------------------
    red = [e for r in judged for e in (list(r.get("code_context") or []) + list(r.get("vulnerable_code") or []))]
    ro  = [e for r in judged for e in (r.get("code_reference_only") or [])]
    allc = [e for r in judged for e in code_entries(r)]
    s["code_context"] = {
        "entries_redistributed": len(red),
        "entries_with_snippet": sum(1 for e in red if e.get("snippet")),
        "entries_reference_only_withheld": len(ro),
        "entries_total_cited": len(allc),
        "redistributed_line_range_verified": sum(1 for e in red if e.get("line_range_verified")),
        "redistrieved_line_range_unverified": sum(1 for e in red if not e.get("line_range_verified")),
        "withheld_by_unresolved_file": sum(1 for e in ro if not e.get("commit_sha")),
        "distinct_files_cited": len({(e.get("commit_sha"), e.get("file")) for e in allc if e.get("file")}),
        "distinct_commits_cited": len({e.get("commit_sha") for e in allc if e.get("commit_sha")}),
        "records_with_any_code_context": sum(1 for r in judged if code_entries(r)),
        "records_with_reference_only_only": sum(
            1 for r in judged if (r.get("code_reference_only") and not snippet_entries(r))
        ),
    }

    # --- taxonomy ----------------------------------------------------------
    cats, classes = collections.Counter(), collections.Counter()
    for r in findings:
        for cl in r["finding"].get("vulnerability_classes") or []:
            classes[cl] += 1
            cats[cl.split("/")[0].strip()] += 1
    s["taxonomy"] = {
        "distinct_classes": len(classes),
        "distinct_top_level_categories": len(cats),
        "by_class": _sorted_counter(classes),
        "by_category": _sorted_counter(cats),
        "findings_with_no_class": sum(1 for r in findings if not (r["finding"].get("vulnerability_classes") or [])),
    }

    # --- provenance --------------------------------------------------------
    urls = [u for r in judged for u in (r.get("provenance", {}).get("source_urls") or [])]
    sha_re = re.compile(r"^https://github\.com/[^/]+/[^/]+/blob/([0-9a-f]{40})/")
    s["provenance"] = {
        "blob_permalinks": sum(1 for u in urls if "/blob/" in u),
        "blob_permalinks_with_40_hex_sha": sum(1 for u in urls if sha_re.match(u)),
        "distinct_permalink_commits": len({m.group(1) for u in urls if (m := sha_re.match(u))}),
        "issue_or_comment_urls": sum(1 for u in urls if "/issues/" in u),
        "non_github_urls": sorted({u for u in urls if not u.startswith("https://github.com/")}),
        "records_with_no_url": sum(1 for r in judged if not (r.get("provenance", {}).get("source_urls"))),
    }

    # --- splits ------------------------------------------------------------
    s["splits"] = {
        "counts": {k: len(v) for k, v in sorted(splits.items())},
        "by_repository": {k: _sorted_counter(collections.Counter(r["source"]["repository"] for r in v)) for k, v in sorted(splits.items())},
        "distinct_records": len({rec_id(r) for v in splits.values() for r in v}),
        "union_equals_findings": {rec_id(r) for v in splits.values() for r in v} == {rec_id(r) for r in findings},
    }

    # --- derived layer (populated once the enrichment scripts have run) ----
    dv = DERIVED / "manifest.json"
    s["derived_layer"] = {
        "present": dv.exists(),
        "files": json.loads(dv.read_text(encoding="utf-8")) if dv.exists() else {},
    }
    return s


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="fail if the report on disk is stale")
    ap.add_argument("--stdout", action="store_true", help="print instead of writing")
    args = ap.parse_args()

    stats = build_stats()
    out = REPORTS / "dataset_stats.json"
    if args.stdout:
        print(json.dumps(stats, indent=2, sort_keys=True, ensure_ascii=False))
        return 0
    if args.check:
        if not out.exists():
            log("MISSING reports/dataset_stats.json")
            return 1
        on_disk = json.loads(out.read_text(encoding="utf-8"))
        if on_disk != stats:
            log("STALE reports/dataset_stats.json — run: python scripts/generate_stats.py")
            return 1
        log("reports/dataset_stats.json is current")
        return 0
    write_json(out, stats)
    log(f"wrote {out.relative_to(ROOT)}  "
        f"findings={stats['findings']['total']} negatives={stats['negatives']['total']} "
        f"exploits={stats['exploits']['records']} patches={stats['patches']['records']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())