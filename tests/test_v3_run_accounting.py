"""Unit tests for the V3 run-accounting manifest keys.

Run:  python -m unittest tests.test_v3_run_accounting
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import v32_execution as X  # noqa: E402

ACCOUNTING_KEYS = {
    "candidate_artefacts",
    "execution_attempts",
    "successful_executions",
    "failed_executions",
    "blocked_executions",
    "evidence_admitted_records",
}


def _run(finding_id: str, status: str, rc) -> dict:
    run = {"finding_id": finding_id, "status": status}
    if rc is not None:
        run["test"] = {"rc": rc, "test_function": "testExploit"}
    return run


def _candidate(cid: str, level: str = "L3", has_experiment: bool = True) -> dict:
    row = {"candidate_id": cid, "verification_level": level,
           "decision": "IMPORT"}
    if has_experiment:
        row["experiment"] = {"level_awarded": level}
    return row


def _record(level: str) -> dict:
    return {"finding_id": "x", "verification_level": level}


def _accounting(runs: list[dict], ledger: list[dict] | None = None,
                records: list[dict] | None = None) -> dict:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "reports" / "v3").mkdir(parents=True)
        (root / "reports" / "v3" / "experimental_proof.json").write_text(
            json.dumps({"runs": runs}), encoding="utf-8")
        return X.run_accounting(root, ledger or [], records or [])


class TestRunAccountingCounts(unittest.TestCase):
    def test_keys_are_the_manifest_contract(self):
        result = _accounting([])
        self.assertEqual(set(result["counts"]), ACCOUNTING_KEYS)

    def test_partition_counts_each_run_once(self):
        runs = [
            _run("a", "violation_observed", 0),
            _run("b", "executed_no_profit_evidence", 0),
            _run("c", "test_failed", 1),
            _run("d", "blocked", 1),
        ]
        ledger = [_candidate("a"), _candidate("b"), _candidate("c", has_experiment=False)]
        records = [_record("L3"), _record("L5"), _record("L0")]
        result = _accounting(runs, ledger, records)
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["counts"]["execution_attempts"], 4)
        self.assertEqual(result["counts"]["successful_executions"], 2)
        self.assertEqual(result["counts"]["failed_executions"], 1)
        self.assertEqual(result["counts"]["blocked_executions"], 1)
        self.assertEqual(result["counts"]["candidate_artefacts"], 2)
        self.assertEqual(result["counts"]["evidence_admitted_records"], 2)

    def test_committed_proof_and_ledgers(self):
        ledger = [json.loads(line) for line in
                  (ROOT / "derived_v3" / "candidate_ledger.jsonl")
                  .open(encoding="utf-8") if line.strip()]
        records = [json.loads(line) for line in
                   (ROOT / "derived_v3" / "records.jsonl")
                   .open(encoding="utf-8") if line.strip()]
        result = X.run_accounting(ROOT, ledger, records)
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["counts"], {
            "candidate_artefacts": 127,
            "execution_attempts": 18,
            "successful_executions": 12,
            "failed_executions": 1,
            "blocked_executions": 5,
            "evidence_admitted_records": 127,
        })
        self.assertEqual(
            result["counts"]["execution_attempts"],
            result["counts"]["successful_executions"]
            + result["counts"]["failed_executions"]
            + result["counts"]["blocked_executions"])


class TestRunAccountingBadData(unittest.TestCase):
    def test_duplicate_run_id_is_not_counted_twice(self):
        result = _accounting([
            _run("a", "violation_observed", 0),
            _run("a", "violation_observed", 0),
        ])
        self.assertTrue(result["errors"])
        self.assertTrue(any("more than once" in e for e in result["errors"]))
        self.assertEqual(result["counts"]["execution_attempts"], 1)
        self.assertEqual(result["counts"]["successful_executions"], 1)

    def test_blocked_with_passing_rc_is_overlap(self):
        result = _accounting([_run("a", "blocked", 0)])
        self.assertTrue(any("blocked but its test rc=0" in e
                            for e in result["errors"]))
        self.assertEqual(result["counts"]["blocked_executions"], 1)
        self.assertEqual(result["counts"]["successful_executions"], 0)
        self.assertEqual(result["counts"]["execution_attempts"], 1)

    def test_failed_with_passing_rc_is_overlap(self):
        result = _accounting([_run("a", "test_failed", 0)])
        self.assertTrue(any("test_failed but its test rc=0" in e
                            for e in result["errors"]))

    def test_run_outside_the_three_categories_is_reported(self):
        result = _accounting([_run("a", "mystery", 1)])
        self.assertTrue(any("fits no accounting category" in e
                            for e in result["errors"]))
        self.assertTrue(any("attempts 1 !=" in e for e in result["errors"]))
        self.assertEqual(result["counts"]["execution_attempts"], 1)
        self.assertEqual(
            result["counts"]["successful_executions"]
            + result["counts"]["failed_executions"]
            + result["counts"]["blocked_executions"], 0)

    def test_missing_rc_is_not_success(self):
        result = _accounting([_run("a", "violation_observed", None)])
        self.assertTrue(result["errors"])
        self.assertEqual(result["counts"]["successful_executions"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)