#!/usr/bin/env python3
"""Per-record audit matrix: one row per finding, for a human curator.

`scripts/validate.py` fails the build on a broken record. This answers the other
question: for *every* record, what evidence do we actually have? It emits a flat
table rather than nested records, so it can be sorted, diffed between builds, and
checked by eye — which is how a dataset curator finds the 40 records whose
provenance is weaker than the rest.

    python scripts/audit_records.py                 # reports/record_audit.jsonl
    python scripts/audit_records.py --summary-only
"""

from __future__ import annotations

import argparse
import collections
import csv
import io
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vlun import (  # noqa: E402
    DERIVED, REPORTS, SPLITS, SPLITS_DIR, WORK, load_core, log, read_jsonl, write_json,
)

FAMILY_KEY = {"findings.jsonl": "findings", "negative_findings.jsonl": "negatives"}

COLUMNS = [
    "record_id", "family", "repository", "severity", "record_class", "status",
    "split", "evidence_types", "provenance", "code_context", "verification",
    "attacker_kind", "attacker_basis", "state_transition", "invariants",
    "taxonomy_class", "license_class", "redistribution_flag", "poc_type",
    "issues",
]


def split_index() -> dict[str, str]:
    out = {}
    for s in SPLITS:
        for r in read_jsonl(SPLITS_DIR / f"{s}.jsonl"):
            out[(r.get("finding") or {}).get("id") or r.get("id")] = s
    return out


def verification_index() -> dict:
    idx = {}
    d = WORK / "poc_runs"
    for f in sorted(d.glob("*.json")) if d.exists() else []:
        if f.name == "_all.json":
            continue
        import json
        for v in json.loads(f.read_text(encoding="utf-8")).get("verdicts", []):
            idx[v["finding_id"]] = v
    return idx


def row_for(rec: dict, family: str, split: str, v: dict | None) -> dict:
    f = rec.get("finding") or {}
    rid = f.get("id") or rec.get("id") or ""
    issues = []
    if not (rec.get("provenance", {}) or {}).get("source_urls"):
        issues.append("no_provenance_url")
    # A rejected submission genuinely has no judged severity; that is the dataset
    # working as designed, so it is not counted as a defect.
    if not (f.get("severity") or "").strip() and family == "findings.jsonl":
        issues.append("no_severity")
    if family == "negative_findings.jsonl" and (f.get("severity") or "").strip():
        issues.append("rejected_record_has_severity")
    if v and v.get("verdict") == "reproduced":
        if not (v.get("evidence") or {}).get("forge_status"):
            issues.append("reproduced_without_forge_status")

    return {
        "record_id": rid,
        "family": family,
        "repository": rec["source"].get("repository"),
        "severity": f.get("severity"),
        "record_class": f.get("record_class"),
        "status": f.get("status"),
        "split": split,
        "evidence_types": "",
        "provenance": "high" if (rec.get("provenance", {}) or {}).get("source_urls") else "low",
        "code_context": "yes" if (rec.get("code_context") or rec.get("vulnerable_code")) else
                        ("reference_only" if rec.get("code_reference_only") else "none"),
        "verification": (v or {}).get("verdict", "not_attempted"),
        "attacker_kind": "",
        "attacker_basis": "",
        "state_transition": "",
        "invariants": len(((rec.get("security_reasoning") or {}).get("invariants") or [])),
        "taxonomy_class": "",
        "license_class": "",
        "redistribution_flag": "",
        "poc_type": (v or {}).get("poc_type", ""),
        "issues": ";".join(issues),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--summary-only", action="store_true")
    ap.add_argument("--derive", action="store_true",
                    help="join the derived layer's attacker model and taxonomy")
    args = ap.parse_args()

    core = load_core()
    splits = split_index()
    ver = verification_index()

    derived_by_fid = {}
    if args.derive:
        for r in read_jsonl(DERIVED / "records.jsonl"):
            fid = r["finding"].get("id")
            if fid:
                derived_by_fid[fid] = r

    rows = []
    for family in ("findings.jsonl", "negative_findings.jsonl"):
        for rec in core[FAMILY_KEY[family]]:
            f = rec.get("finding") or {}
            rid = f.get("id") or ""
            row = row_for(rec, family, splits.get(rid, "unassigned"),
                          ver.get(rid))
            d = derived_by_fid.get(rid)
            if d:
                am = d["attacker_model"]["attacker_identity"]
                row["evidence_types"] = ",".join(d["evidence"]["evidence_types_present"])
                row["attacker_kind"] = am["value"]
                row["attacker_basis"] = am["evidence_type"]
                row["state_transition"] = "yes" if d["security_state_transition"]["present"] else "no"
                row["taxonomy_class"] = f'{d["taxonomy"]["category"]}/{d["taxonomy"]["class"]}'
                row["license_class"] = d["license_classification"]
                row["redistribution_flag"] = d["redistribution"]["flag"] or "none"
            rows.append(row)

    if not args.summary_only:
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(rows)
        (REPORTS / "record_audit.csv").write_text(buf.getvalue(), encoding="utf-8", newline="")
        log(f"wrote reports/record_audit.csv ({len(rows)} rows)")

    summary = {
        "generated_by": "scripts/audit_records.py",
        "records": len(rows),
        "by_verification": dict(collections.Counter(r["verification"] for r in rows)),
        "by_code_context": dict(collections.Counter(r["code_context"] for r in rows)),
        "by_attacker_kind": dict(collections.Counter(r["attacker_kind"] for r in rows if r["attacker_kind"])),
        "by_provenance": dict(collections.Counter(r["provenance"] for r in rows)),
        "by_split": dict(collections.Counter(r["split"] for r in rows)),
        "records_with_invariant": sum(1 for r in rows if r["invariants"]),
        "records_with_issues": sum(1 for r in rows if r["issues"]),
        "issue_kinds": dict(collections.Counter(
            k for r in rows for k in r["issues"].split(";") if k)),
        "weakest_provenance_records": [r["record_id"] for r in rows if r["provenance"] == "low"][:40],
    }
    write_json(REPORTS / "record_audit_summary.json", summary)
    log(f"records={summary['records']} issues={summary['records_with_issues']} "
        f"{summary['issue_kinds']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())