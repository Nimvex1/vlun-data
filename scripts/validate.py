#!/usr/bin/env python3
"""The build gate. Fails the build on critical integrity problems.

    python scripts/validate.py            # run every check, exit non-zero on failure
    python scripts/validate.py --quiet
    python scripts/validate.py --online   # also probe that cited URLs resolve

Checks, grouped by what they protect:

  structure     JSON/JSONL validity, schema shape, record uniqueness
  provenance    required provenance, URL and commit format, mutable-ref flagging
  consistency   statistics, severity, PoC, patch, licence, negative labels
  evidence      every evidence_type is in the closed vocabulary; no
                experimentally_verified without a run artefact behind it
  splits        repository isolation, id isolation, cross-split duplicates
  v2.1          experimental claims are backed by run artefacts, the new
                vocabularies are closed, subsets obey their admission rules, and
                the new leakage detectors report zero
  v2.2          the multi-language layer passes its own gate, derived_v2_2 and
                splits_v2_2 resolve record-for-record with matching sha256,
                experiment claims point at artefacts that exist, and every
                benchmark family A-Q exists with rows whose answer keys can be
                rebuilt from the records (scripts/check_ml_layer.py reports the
                same ml-layer result this gate re-runs in-process)

`reported_statistics == computed_statistics` is enforced by regenerating the
stats in-process and comparing against reports/dataset_stats.json on disk.
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vlun import (  # noqa: E402
    DATASET_VERSION, REPORTS, log, write_json,
)
from validate_checks import (  # noqa: E402
    check_audit_sources, check_consistency,
    check_derived_layer, check_evidence, check_online,
    check_provenance, check_splits, check_structure,
    check_v21, check_v22, check_v22_layer, load_core_dict,
)

class Report:
    def __init__(self, quiet: bool = False):
        self.checks: list[dict] = []
        self.quiet = quiet

    def add(self, group: str, check: str, ok: bool, failures=None, detail=None, critical=True):
        fails = list(failures or []) if not ok else []
        self.checks.append({"group": group, "check": check, "ok": bool(ok),
                            "critical": critical,
                            "failure_count": len(fails),
                            "failures": fails[:25],
                            "detail": detail})
        if not self.quiet:
            mark = "ok  " if ok else ("FAIL" if critical else "warn")
            extra = f"  ({len(fails)} failures)" if fails else ""
            log(f"  [{mark}] {group}/{check}{extra}")
            if fails:
                for f in fails[:5]:
                    log(f"         - {f}")
        return ok



def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--online", action="store_true", help="probe cited URLs (slow, network)")
    args = ap.parse_args()

    rep = Report(args.quiet)
    log("validate.py")

    core, bad_json = load_core_dict()
    check_structure(rep, core, bad_json)
    derived_mutable = check_provenance(rep, core)
    splits = check_consistency(rep, core)
    check_evidence(rep, core)
    check_splits(rep, splits)
    check_derived_layer(rep)
    check_online(rep, core, args.online)
    check_v21(rep, derived_mutable)
    check_v22(rep)
    check_v22_layer(rep)
    check_audit_sources(rep)

    # --------------------------------------------------------------- summary
    # Computed LAST, after every check has been added, so that a failure in any
    # group can reach the exit code.
    crit = [c for c in rep.checks if not c["ok"] and c["critical"]]
    warns = [c for c in rep.checks if not c["ok"] and not c["critical"]]

    summary = {
        "generated_by": "scripts/validate.py",
        "dataset_version": DATASET_VERSION,
        "checks": len(rep.checks),
        "passed": sum(1 for c in rep.checks if c["ok"]),
        "failed_critical": len(crit),
        "warnings": len(warns),
        "groups": dict(collections.Counter(c["group"] for c in rep.checks)),
        "details": rep.checks,
    }
    write_json(REPORTS / "validation_report.json", summary)

    # close the loop on the v2.1 summary: the gate is the last stage, so it is
    # the only place that knows whether the build actually passed
    v21 = REPORTS / "v2_1_summary.json"
    if v21.exists():
        doc = json.loads(v21.read_text(encoding="utf-8"))
        doc["validation_failures"] = len(crit)
        doc["validation_warnings"] = len(warns)
        doc["validation_checks_passed"] = f"{summary['passed']}/{summary['checks']}"
        doc["validation_failed_checks"] = [
            {"group": c["group"], "check": c["check"], "failures": c.get("failures")}
            for c in rep.checks if not c["ok"]]
        write_json(v21, doc)

    log(f"\n{summary['passed']}/{summary['checks']} checks passed; "
        f"{summary['failed_critical']} critical failures, {summary['warnings']} warnings")
    if crit:
        for c in crit:
            log(f"  CRITICAL: {c['group']}/{c['check']} ({c['failure_count']})")
        log("BUILD FAILED")
        return 1
    log("BUILD OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
