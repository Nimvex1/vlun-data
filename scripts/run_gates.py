#!/usr/bin/env python3
"""One runner for all gates, per layer. Exit 1 if any gate fails.

Runs every validator in dependency order and prints a unified PASS/FAIL/
SKIPPED matrix. Network/toolchain-dependent stages report SKIPPED
(skipped_no_network), never silent. Writes only the git-ignored
`reports/gate_run.json` machine-readable matrix (not a committed artefact).

    python scripts/run_gates.py
    python scripts/run_gates.py --quiet
    python scripts/run_gates.py --only vbeta   # subset: v1 v3 v31 vbeta manifests repro tests readme
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable

GATES = [
    ("v1-authorship", [PY, "scripts/validate.py", "--quiet"]),
    ("ml-layer", [PY, "scripts/check_ml_layer.py", "--quiet"]),
    ("v3", [PY, "scripts/validate_v3.py", "--quiet"]),
    ("v31", [PY, "scripts/validate_v31.py", "--quiet"]),
    ("vbeta-gate", [PY, "Vbeta/scripts/validate_vbeta.py", "--quiet"]),
    ("manifests", [PY, "scripts/check_manifests.py", "--quiet"]),
    ("line-endings", [PY, "scripts/check_line_endings.py", "--quiet"]),
    ("reproducibility", [PY, "scripts/check_reproducibility.py", "--quiet"]),
    ("unit-tests", [PY, "-m", "unittest", "discover", "-s", "tests"]),
    ("vbeta-tests", [PY, "Vbeta/tests/test_vbeta.py"]),
    ("readme-current", [PY, "scripts/generate_readme.py", "--check"]),
    ("solodit-report-current",
     [PY, "Vbeta/scripts/build_solodit_report.py", "--check"]),
    ("repro-report-current", [PY, "scripts/build_repro_report.py", "--check"]),
    ("stats-current", [PY, "scripts/generate_stats.py", "--check"]),
    # Report freshness is independent of semantic validation: this gate
    # proves extraction_errors.json and final_quality_report.md equal a
    # regeneration. Finding resolution state lives in the JSON itself.
    ("reports-current", [PY, "scripts/generate_reports.py", "--check"]),
    # Rejection evidence: the canonical corpus and the report that reads it.
    # Both must be current, and the corpus is what the six rejection axes are
    # defined by, so a hand-edited negative count fails here.
    ("rejection-corpus-current",
     [PY, "scripts/build_rejection_corpus.py", "--check"]),
    ("negative-stats-current", [PY, "scripts/classify_negatives.py", "--check"]),
    # ...and the two must agree with the corpus on every axis, or the gate fails.
    ("rejection-consistency", [PY, "scripts/check_rejection_consistency.py", "--quiet"]),
    # The F-extension (F-A six-axis vectors, F-B duplicate-radar pairs) is emitted
    # from the same canonical corpus, so its rows, answer keys, manifest entries and
    # reports are checked by recomputing from that corpus and the `jsonl/` layer:
    # axis gold, duplicate-is-not-technical, packet/pair leakage, pair adjudication,
    # inherited splits and every published count.
    ("f-extension-consistency", [PY, "scripts/check_f_extension.py", "--check"]),
    # ...and the emitted rows and the published floors must equal a regeneration,
    # so a hand-edited task file or a stale baseline number fails on its own.
    ("f-extension-current", [PY, "scripts/build_f_extension.py", "--check"]),
    ("f-extension-baselines-current",
     [PY, "scripts/score_f_extension.py", "--check"]),
    # VLUN-Prove: the published interface must equal a regeneration, and the
    # private answer key must still match its published commitment. Skips (rc=2)
    # on a machine without the private split, because the split is not committed.
    ("prove-split-current", [PY, "scripts/build_prove_split.py", "--check"]),
    # The candidate ledger is what stops the Prove pool from being described by its
    # run count: a row may only claim `qualified` with the admission-gate fields, and
    # blocked rows keep their blocker.
    ("prove-ledger-current", [PY, "scripts/build_prove_ledger.py", "--check"]),
    # Rights: no contradictory licence status, no copied expressive content in the
    # distribution view, no un-negotiated reuse claim, no drifted count. The
    # V4 licence fields must still match the recorded decision in V4/licensing.json.
    ("rights-consistency", [PY, "scripts/check_rights_consistency.py", "--quiet"]),
    ("v4-licensing-current", [PY, "scripts/reconcile_v4_licensing.py", "--check"]),
    # Execution density (item 6) and the blocked-run recovery attempts (item 7):
    # the queue and every attempt report must equal a regeneration from the
    # artefacts on disk, so a run count cannot be edited by hand.
    ("poc-triage-current", [PY, "scripts/build_poc_triage_queue.py", "--check"]),
    ("poc-attempts-current", [PY, "scripts/rerun_v1_pocs.py", "--check"]),
    ("v32-attempts-current", [PY, "scripts/unblock_v32_runs.py", "--check"]),
    # Evidence-span task family (item 10).
    ("span-audit-current", [PY, "scripts/audit_evidence_spans.py", "--check"]),
    ("span-tasks-current", [PY, "scripts/build_span_tasks.py", "--check"]),
    ("span-scoring-current", [PY, "scripts/score_span_tasks.py", "--check"]),
    # Root-cause taxonomy (item 16) and the IAA study state (item 14).
    ("taxonomy-current", [PY, "scripts/validate_taxonomy.py", "--check"]),
    ("root-cause-assignments-current", [PY, "scripts/assign_root_causes.py", "--check"]),
    ("iaa-sample-current", [PY, "scripts/sample_iaa.py", "--check"]),
    ("iaa-stats-current", [PY, "scripts/iaa_statistics.py", "--check"]),
    # API-sibling layer (item 11): the builder's candidates and the independent
    # reviewer's admitted set must both equal a regeneration.
    ("api-siblings-current", [PY, "scripts/build_api_siblings.py", "--check"]),
    ("sibling-review-current", [PY, "scripts/review_sibling_pairs.py", "--check"]),
    # The before/after summary is generated, so it cannot drift from the reports.
    ("remediation-report-current",
     [PY, "scripts/build_remediation_report.py", "--check"]),
    # Same rule for the set-aside list: what the pipeline refused must be
    # recomputed from the artefacts, not remembered in prose.
    ("quarantine-report-current",
     [PY, "scripts/build_quarantine_report.py", "--check"]),
    ("field-coverage-current", [PY, "scripts/field_coverage.py", "--check"]),
    # Packaging gates the CI workflow already ran separately. Without these
    # a local `run_gates.py` reported green while CI failed on a stale
    # datasheet or schema, so local green did not mean mergeable.
    ("schemas-current", [PY, "scripts/build_schemas.py", "--check"]),
    ("datasheet-current", [PY, "scripts/build_datasheet.py", "--check"]),
    ("vbeta-build-current",
     [PY, "Vbeta/scripts/build_vbeta.py", "--check"]),
    # The JSON catalog maps every committed .json/.jsonl by category without
    # moving anything; a new data file without a catalog entry fails here.
    ("catalog-current", [PY, "scripts/build_json_catalog.py", "--check"]),
    # Independent benchmark-validity layer (additive; --check only, so the
    # gate cannot regenerate the audit it is verifying).
    ("benchmark-audit-current",
     [PY, "scripts/independent_benchmark_audit.py", "--check"]),
    ("benchmark-holdout-current",
     [PY, "scripts/build_secondary_holdout.py", "--check"]),
    # The published scores must equal a fresh calculation: the six baseline
    # reports and the metric report are regenerated and compared, so a
    # hand-edited number fails here.
    ("benchmark-baselines-current",
     [PY, "scripts/score_benchmark.py", "--check"]),
    ("benchmark-metrics-current",
     [PY, "scripts/score_benchmark.py", "--check-metrics"]),
    # Model inputs must be separable from evaluation answers: no protected
    # evaluation record, answer or payload may be reachable from the
    # model-visible corpus, and the task files must not carry their keys.
    ("eval-leakage", [PY, "scripts/check_eval_leakage.py", "--quiet"]),
    ("eval-leakage-report-current",
     [PY, "scripts/build_eval_leakage_report.py", "--check"]),
    # No generated file may carry a machine-specific path, and the
    # redaction that removes them must itself be reproducible.
    ("no-machine-paths", [PY, "scripts/check_no_machine_paths.py", "--quiet"]),
    ("redaction-current",
     [PY, "scripts/redact_machine_paths.py", "--check"]),
    # The release manifest is the machine-readable answer to "may this file
    # be redistributed?"; it must equal a fresh classification.
    ("release-manifest-current",
     [PY, "scripts/build_release_manifest.py", "--check"]),
    # V3.2 execution provenance: every recorded artefact hash must match
    # the committed bytes (network-free, machine-independent).
    ("proof-hashes-current",
     [PY, "scripts/reconcile_proof_artefact_hashes.py", "--check"]),
    # Risk-based inventory: every script is classified, and production
    # mutation/publication paths are either gated or explicitly excepted.
    ("gate-coverage", [PY, "scripts/gate_coverage.py", "--check"]),
]

ONLY_MAP = {
    "v1": ["v1-authorship", "ml-layer"],
    "v3": ["v3"],
    "v31": ["v31"],
    "vbeta": ["vbeta-gate", "vbeta-tests"],
    "manifests": ["manifests"],
    "line-endings": ["line-endings"],
    "repro": ["reproducibility"],
    "tests": ["unit-tests", "vbeta-tests"],
    "readme": ["readme-current", "stats-current", "field-coverage-current",
               "solodit-report-current", "repro-report-current"],
    "reports": ["reports-current"],
    "inventory": ["gate-coverage"],
    # `rejection`, not `benchmark`: the F-extension's authority is the canonical
    # rejection corpus and the negative-record layer that the other two rejection
    # gates already read, and its gold is that corpus's six axes re-expressed. The
    # `benchmark` group is the scoring/holdout/leakage layer, which reads the rows
    # but does not define them.
    "rejection": ["rejection-corpus-current", "negative-stats-current",
                  "rejection-consistency",
                  "f-extension-consistency", "f-extension-current",
                  "f-extension-baselines-current"],
    "prove": ["prove-split-current", "prove-ledger-current"],
    "rights": ["rights-consistency", "v4-licensing-current"],
    "execution": ["poc-triage-current", "poc-attempts-current",
                  "v32-attempts-current"],
    "spans": ["span-audit-current", "span-tasks-current", "span-scoring-current"],
    "taxonomy": ["taxonomy-current", "root-cause-assignments-current",
                 "iaa-sample-current", "iaa-stats-current"],
    "siblings": ["api-siblings-current", "sibling-review-current"],
    "summary": ["remediation-report-current", "quarantine-report-current"],
    "packaging": ["schemas-current", "datasheet-current", "vbeta-build-current"],
    "catalog": ["catalog-current"],
    "benchmark": ["benchmark-audit-current", "benchmark-holdout-current",
                  "benchmark-baselines-current", "benchmark-metrics-current",
                  "eval-leakage", "eval-leakage-report-current"],
    "paths": ["no-machine-paths", "redaction-current"],
    "release": ["release-manifest-current"],
    "proof": ["proof-hashes-current"],
}

# Exit code 2 means SKIPPED (missing optional inputs, no network): recorded
# as skipped, never as pass and never as failure. check_ml_layer.py returns
# 2 when jsonl_ml/ is absent; network-gated validators use the same
# convention via skipped_no_network. Exit 0 is PASS; any other code, a
# timeout, or a launch error is FAIL. A skip message with exit 0 is a
# defect in the child, not a skip.
SKIPPED_CODES = {2}

# Machine-local matrix. Committed reports must not depend on which optional
# inputs this checkout holds, so this file is git-ignored.
GATE_RUN_PATH = ROOT / "reports" / "gate_run.json"


def classify_status(returncode: int | None, *, error: str | None = None) -> str:
    """Map a child process outcome to PASS / FAIL / SKIPPED.

    Unexpected return codes, launch failures and timeouts are FAIL, never
    SKIPPED: converting a failure into a skip to keep a run green is
    forbidden.
    """
    if error:
        return "FAIL"
    if returncode == 0:
        return "PASS"
    if returncode in SKIPPED_CODES:
        return "SKIPPED"
    return "FAIL"


def write_gate_run(*, configured: int, selected: list[tuple[str, list]],
                   results: list[tuple[str, str]], records: list[dict]) -> None:
    """Write the git-ignored per-run matrix. Never a committed artefact."""
    nfail = sum(1 for _, st in results if st == "FAIL")
    nskip = sum(1 for _, st in results if st == "SKIPPED")
    npass = sum(1 for _, st in results if st == "PASS")
    payload = {
        "generated_by": "scripts/run_gates.py",
        "configured_gates": configured,
        "selected_gates": len(selected),
        "pass": npass,
        "fail": nfail,
        "skipped": nskip,
        "reconciles": (npass + nfail + nskip) == len(selected),
        "results": records,
        "note": ("PASS + FAIL + SKIPPED must equal selected_gates. A skip "
                 "records the child's skip line, the missing input it named, "
                 "and that the check did not verify the claim."),
    }
    GATE_RUN_PATH.parent.mkdir(parents=True, exist_ok=True)
    GATE_RUN_PATH.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8", newline="\n")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--only", nargs="*", choices=sorted(ONLY_MAP),
                    help="run a subset of gates")
    args = ap.parse_args()

    want = set(ONLY_MAP) if not args.only else set()
    for key in (args.only or []):
        want.update(ONLY_MAP[key])
    # `want` holds group keys on a full run and gate names under --only;
    # resolve both so --only works instead of KeyErroring on a gate name.
    names: set[str] = set()
    for k in want:
        names.update(ONLY_MAP.get(k, [k]))
    selected = [(name, cmd) for name, cmd in GATES if name in names]
    # --only given explicitly trims to the requested groups.
    if args.only:
        keep = set()
        for key in args.only:
            keep.update(ONLY_MAP[key])
        selected = [(n, c) for n, c in GATES if n in keep]

    results = []
    records = []
    print("run_gates.py")
    print(f"configured={len(GATES)} selected={len(selected)}")
    for name, cmd in selected:
        out = ""
        tail = ""
        error = None
        returncode: int | None = None
        try:
            p = subprocess.run(cmd, cwd=str(ROOT), capture_output=True,
                               text=True, timeout=1200, errors="replace")
            returncode = p.returncode
            out = ((p.stdout or "") + (p.stderr or "")).strip()
            tail = " | ".join(t.strip() for t in out.splitlines()[-2:]
                              if t.strip())
        except subprocess.TimeoutExpired:
            error, tail = "timeout after 1200s", "timeout after 1200s"
        except OSError as exc:
            error = f"cannot start: {exc}"
            tail = error
        status = classify_status(returncode, error=error)
        rec = {
            "name": name,
            "status": status,
            "returncode": returncode,
            "error": error,
            "tail": (tail or "")[:160],
        }
        if status == "SKIPPED":
            rec["skip_reason"] = tail
            rec["missing_input"] = tail
            rec["reproducibility_limitation"] = (
                "optional inputs named in the skip line are absent; this "
                "check did not run and its claim is unverified here")
        results.append((name, status))
        records.append(rec)
        if args.quiet:
            continue
        print(f"  [{status}] {name}"
              + (f" — {tail[:160]}" if tail else ""))
        if status == "FAIL" and out:
            # A failing gate must show WHY, especially on CI where the
            # validator's own log is captured, not streamed.
            lines = out.splitlines()
            show = lines if len(lines) <= 60 else (
                lines[:10]
                + [f"... ({len(lines) - 50} lines elided) ..."]
                + lines[-40:])
            for ln in show:
                print(f"    {ln.strip()}"[:300])

    nfail = sum(1 for _, st in results if st == "FAIL")
    nskip = sum(1 for _, st in results if st == "SKIPPED")
    npass = len(results) - nfail - nskip
    print(f"gates={len(results)} pass={npass} "
          f"fail={nfail} skipped={nskip}")
    if npass + nfail + nskip != len(selected):
        print("FAIL: PASS + FAIL + SKIPPED does not equal selected gates",
              file=sys.stderr)
    write_gate_run(configured=len(GATES), selected=selected,
                   results=results, records=records)
    return overall_rc(results)


def overall_rc(results: list[tuple[str, str]]) -> int:
    """Exit code for a gate run. A green build that ran zero checks is a
    lie, not a pass: every gate skipping (exit 2: missing optional inputs)
    fails the run rather than reporting success with nothing verified."""
    nfail = sum(1 for _, st in results if st == "FAIL")
    npass = sum(1 for _, st in results if st == "PASS")
    if not results or npass == 0:
        print("FAIL: no gate passed; a build that verifies nothing is not green",
              file=sys.stderr)
        return 1
    return 1 if nfail else 0


if __name__ == "__main__":
    raise SystemExit(main())
