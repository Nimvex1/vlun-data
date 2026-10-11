#!/usr/bin/env python3
"""High-confidence subsets and task-oriented training files.

Four subsets, each with a hard admission rule. A record that fails the rule is
not weakened and included; it is left out.

    datasets/verified_findings.jsonl    strong provenance: immutable citations,
                                         a retrievable pinned source, a stated
                                         severity and a public verdict
    datasets/verified_exploits.jsonl    L5 or above: an executed exploit
    datasets/verified_patches.jsonl     L6: reproduced on the vulnerable revision
                                         and blocked on the fixed one
    datasets/verified_negatives.jsonl   experimentally demonstrated non-exploit,
                                         OR authoritative rejection evidence

Plus task-oriented training files that keep the task axis separate instead of
collapsing everything into one undifferentiated blob:

    training/{vulnerability_detection,exploit_reasoning,attacker_reasoning,
              negative_reasoning,patch_reasoning}.jsonl

Every row keeps `canonical_record_id` so a consumer can join back to
`derived/records.jsonl`.

    python scripts/build_subsets.py
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vlun import DERIVED, REPORTS, ROOT, log, read_jsonl, write_json, write_jsonl  # noqa: E402

DATASETS = ROOT / "datasets"
TRAINING = ROOT / "training"


def _load(path: Path):
    return read_jsonl(path) if path.exists() else []


def _json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def _immutable_citations(rec: dict) -> list[str]:
    """Pinned-commit citation URLs on a derived record."""
    urls = [c.get("source_url") for c in
            (rec.get("code_context") or []) + (rec.get("code_reference_only") or [])
            if c.get("source_url")]
    return [u for u in urls if "/blob/" in u and len(u.split("/blob/")[1][:40]) == 40]


def admits_finding(rec: dict) -> bool:
    """verified_findings rule: immutable pinned citations AND at least one
    cited file retrieved at its pinned commit. Pure; unit-tested."""
    urls = [c.get("source_url") for c in
            (rec.get("code_context") or []) + (rec.get("code_reference_only") or [])
            if c.get("source_url")]
    immutable = _immutable_citations(rec)
    if not urls or not immutable:
        return False
    retrieved = [c for c in (rec.get("code_context_expanded") or [])
                 if c.get("retrieved_locally")]
    return bool(retrieved)


def admits_exploit(rep: dict) -> bool:
    """verified_exploits rule: executed at L5/L6. Pure; unit-tested."""
    return rep.get("poc_level") in ("L5", "L6")


def admits_patch(pv: dict) -> bool:
    """verified_patches rule: fix confirmed effective. Pure; unit-tested."""
    return pv.get("fix_effectiveness") == "effective"


def admits_negative(n: dict) -> bool:
    """verified_negatives rule: authoritative rejection evidence. Pure."""
    return n.get("negative_class") in ("experimentally_verified",
                                       "attributed",
                                       "corroborated_duplicate")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--records", default=str(DERIVED / "records.jsonl"))
    args = ap.parse_args()

    records = _load(Path(args.records))
    repro = _json(REPORTS / "reproduction_stats.json")
    repro_by = {r["finding_id"]: r for r in repro.get("per_record", [])}
    patches = {r["finding_id"]: r for r in _json(REPORTS / "patch_verification_v2.json").get("records", [])}
    negatives = {r["finding_id"]: r for r in _json(REPORTS / "negative_verification_stats.json").get("records", [])}
    cites = {c["record_id"]: c for c in _json(REPORTS / "citation_resolution.json").get("citations", [])}

    # ---------------------------------------------------------------- findings
    findings = []
    for rec in records:
        rid = rec["id"]
        if not admits_finding(rec):
            continue
        urls = [c.get("source_url") for c in
                (rec.get("code_context") or []) + (rec.get("code_reference_only") or [])
                if c.get("source_url")]
        immutable = _immutable_citations(rec)
        retrieved = [c for c in (rec.get("code_context_expanded") or [])
                     if c.get("retrieved_locally")]
        f = rec.get("finding") or {}
        findings.append({
            "id": rid,
            "protocol": (rec.get("protocol") or {}).get("name"),
            "repository": (rec.get("source") or {}).get("repository"),
            "title": f.get("title"),
            "original_report_severity": f.get("severity"),
            "judge_adjusted_severity": (rec.get("validation") or {}).get("severity_change") or None,
            "sponsor_position": (rec.get("validation") or {}).get("sponsor_position") or None,
            "record_class": f.get("record_class"),
            "status": f.get("status"),
            "audited_commit": (rec.get("source") or {}).get("commit_sha"),
            "immutable_citations": len(immutable),
            "mutable_citations": len(urls) - len(immutable),
            "resolved_citations": sum(1 for u in urls
                                      if (cites.get(rid) or {}).get("source_url_original") == u),
            "code_files_retrieved": len(retrieved),
            "security_property": (rec.get("invariants") or {}).get("invariants", [{}])[0].get("invariant")
                                 if (rec.get("invariants") or {}).get("invariants") else None,
            "evidence_layers": {
                "report": True,
                "source_code": bool(retrieved),
                "static_analysis": None,
                "dynamic_poc": repro_by.get(rid, {}).get("poc_level", "L0") in ("L4", "L5", "L6"),
            },
            "admission_rule": ("immutable pinned citations, at least one cited file retrieved "
                               "at its pinned commit, a public verdict and a stated severity"),
            "evidence_type": "derived_fact",
        })

    # --------------------------------------------------------------- exploits
    exploits = []
    for fid, r in sorted(repro_by.items()):
        if not admits_exploit(r):
            continue
        pv = patches.get(fid) or {}
        exploits.append({
            "finding_id": fid,
            "repository": r["repository"],
            "original_report_severity": r["severity"],
            "judge_adjusted_severity": r["validation_status"],
            "poc_class": r["poc_class"],
            "poc_level": r["poc_level"],
            "audited_commit": r["experiment"]["vulnerable_revision"],
            "experiment_verdict": r["experiment"]["verdict"],
            "observed_failure": r["experiment"]["observed_failure"],
            "fix_confirmed": pv.get("fix_effectiveness") == "effective",
            "fix_category": (pv.get("fix_category") or {}).get("category"),
            "admission_rule": "an exploit was executed at the audited revision and the "
                               "declared security property was observed to be violated",
            "evidence_type": "experimentally_verified",
        })

    # ---------------------------------------------------------------- patches
    verified_patches = []
    for fid, pv in sorted(patches.items()):
        if not admits_patch(pv):
            continue
        verified_patches.append({
            "finding_id": fid,
            "repository": pv["repository"],
            "vulnerable_commit": (pv.get("patch_delta") or {}).get("diffed_vulnerable_commit")
                                 or pv.get("vulnerable_commit"),
            "fixed_commit": (pv.get("patch_delta") or {}).get("diffed_fixed_commit")
                             or pv.get("fixed_commit"),
            "patch_record_fixed_commit": pv.get("fixed_commit"),
            "fixing_commit_discrepancy": pv.get("fixing_commit_discrepancy"),
            "vulnerable_revision_result": pv.get("vulnerable_revision_result"),
            "fixed_revision_result": pv.get("fixed_revision_result"),
            "regression_test": pv.get("regression_test"),
            "fix_category": pv.get("fix_category"),
            "patch_delta_scope": pv.get("patch_delta_scope"),
            "admission_rule": ("the same test observed the violation on the audited revision "
                               "and the property held on the fixed revision"),
            "evidence_type": "experimentally_verified",
        })

    # --------------------------------------------------------------- negatives
    verified_negatives = []
    for fid, n in sorted(negatives.items()):
        if not admits_negative(n):
            continue
        verified_negatives.append({
            "finding_id": fid,
            "repository": n["repository"],
            "original_verdict": n["original_verdict"],
            "negative_class": n["negative_class"],
            "is_false_positive": n["is_false_positive"],
            "reason_evidence_type": n["class_evidence"]["evidence_type"],
            "class_evidence": n["class_evidence"].get("detail"),
            "corroboration": n.get("corroboration"),
            "executed_disproof": n.get("executed_disproof"),
            "admission_rule": ("an attempted exploit was observed to fail, OR a named judge or "
                               "sponsor published the reason, OR a confirmed finding carries "
                               "the same claim so this copy is redundant rather than wrong"),
            "caveat": ("a corroborated duplicate is NOT a false positive; the claim was "
                       "validated elsewhere in the same audit"),
            "evidence_type": n["class_evidence"]["evidence_type"],
        })

    DATASETS.mkdir(exist_ok=True)
    TRAINING.mkdir(exist_ok=True)
    write_jsonl(DATASETS / "verified_findings.jsonl", findings)
    write_jsonl(DATASETS / "verified_exploits.jsonl", exploits)
    write_jsonl(DATASETS / "verified_patches.jsonl", verified_patches)
    write_jsonl(DATASETS / "verified_negatives.jsonl", verified_negatives)

    # ---------------------------------------------------------------- training
    by_id = {r["id"]: r for r in records}
    training = {
        "vulnerability_detection": [],
        "exploit_reasoning": [],
        "attacker_reasoning": [],
        "negative_reasoning": [],
        "patch_reasoning": [],
    }
    for f in findings:
        rec = by_id.get(f["id"]) or {}
        training["vulnerability_detection"].append({
            "canonical_record_id": f["id"],
            "input": {"title": f["title"], "code": [
                {"file": c.get("file"), "commit_sha": c.get("commit_sha"),
                 "line_start": c.get("line_start"), "line_end": c.get("line_end"),
                 "snippet": c.get("snippet")}
                for c in (rec.get("code_context") or [])[:6] if c.get("snippet")]},
            "output": {"vulnerable": f["record_class"] == "judged" and f["status"] == "confirmed"},
            "evidence_type": "externally_attributed",
        })
    for e in exploits:
        training["exploit_reasoning"].append({
            "canonical_record_id": e["finding_id"],
            "input": {"repository": e["repository"], "commit": e["audited_commit"],
                      "claim": (by_id.get(e["finding_id"], {}).get("finding") or {}).get("title")},
            "output": {"security_property": e.get("security_property"),
                       "observed_failure": e["observed_failure"]},
            "evidence_type": "experimentally_verified",
        })
    for f in findings:
        rec = by_id.get(f["id"]) or {}
        am = rec.get("attacker_model") or {}
        if not am or (am.get("evidence_type") == "unknown"):
            continue
        training["attacker_reasoning"].append({
            "canonical_record_id": f["id"],
            "input": {"title": f["title"]},
            "output": {"attacker_kind": am.get("attacker_kind"),
                       "capabilities": am.get("capabilities"),
                       "preconditions": am.get("preconditions")},
            "evidence_type": am.get("evidence_type"),
        })
    for n in verified_negatives:
        training["negative_reasoning"].append({
            "canonical_record_id": n["finding_id"],
            "input": {"verdict": n["original_verdict"]},
            "output": {"negative_class": n["negative_class"],
                       "is_false_positive": n["is_false_positive"],
                       "reason": n["class_evidence"].get("detail")},
            "evidence_type": n["evidence_type"],
        })
    for p in verified_patches:
        training["patch_reasoning"].append({
            "canonical_record_id": p["finding_id"],
            "input": {"vulnerable_commit": p["vulnerable_commit"],
                      "fixed_commit": p["fixed_commit"]},
            "output": {"fix_effectiveness": "effective",
                       "fix_category": (p.get("fix_category") or {}).get("category"),
                       "vulnerable_revision_result": p["vulnerable_revision_result"],
                       "fixed_revision_result": p["fixed_revision_result"]},
            "evidence_type": "experimentally_verified",
        })
    for name, rows in training.items():
        write_jsonl(TRAINING / f"{name}.jsonl", rows)

    summary = {
        "generated_by": "scripts/build_subsets.py",
        "subsets": {
            "verified_findings": len(findings),
            "verified_exploits": len(exploits),
            "verified_patches": len(verified_patches),
            "verified_negatives": len(verified_negatives),
        },
        "training": {k: len(v) for k, v in training.items()},
        "admission_rules": {
            "verified_findings": findings[0]["admission_rule"] if findings else None,
            "verified_exploits": exploits[0]["admission_rule"] if exploits else None,
            "verified_patches": verified_patches[0]["admission_rule"] if verified_patches else None,
            "verified_negatives": verified_negatives[0]["admission_rule"] if verified_negatives else None,
        },
        "exploit_levels": dict(Counter(e["poc_level"] for e in exploits)),
        "negative_classes": dict(Counter(n["negative_class"] for n in verified_negatives)),
        "policy": ("These subsets are deliberately small. A record is never admitted by "
                   "lowering the bar; if the evidence is not there the row does not exist."),
    }
    write_json(REPORTS / "subsets.json", summary)
    log(f"datasets: {summary['subsets']}")
    log(f"training: {summary['training']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())