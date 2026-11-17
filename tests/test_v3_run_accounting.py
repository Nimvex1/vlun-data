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

# The five admitted records that claim a reproduced violation in the shipped
# V3 layer, and nothing more. Pinned by id: a silent sixth L5, or an L5 that
# moves, must fail here rather than in a reader's misreading of the manifest.
SHIPPED_L5_IDS = [
    "defihacklabs:src/test/2024-04/PikeFinance_exp",
    "defihacklabs:src/test/2025-07/SWAPPStaking_exp",
    "defihacklabs:src/test/2026-08/USM_exp",
    "defihacklabs:src/test/2026-09/Flamincome_exp",
    "defihacklabs:src/test/2026-09/Reddio_exp",
]


def _read_jsonl(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def _shipped_layers() -> tuple[list[dict], list[dict]]:
    return (_read_jsonl(ROOT / "derived_v3" / "candidate_ledger.jsonl"),
            _read_jsonl(ROOT / "derived_v3" / "records.jsonl"))


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


def _record(level: str, fid: str = "x") -> dict:
    return {"finding_id": fid, "verification_level": level}


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
        ledger, records = _shipped_layers()
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


class TestEvidenceAdmittedRecordsMeaning(unittest.TestCase):
    """`evidence_admitted_records` is an L3+ record count, never a run count."""

    def test_equals_the_l3_plus_record_count(self):
        records = ([_record("L3", "a"), _record("L3", "b"), _record("L3", "c"),
                    _record("L4", "d"), _record("L5", "e"), _record("L6", "f"),
                    _record("L0", "g"), _record("L1", "h")])
        result = _accounting([], records=records)
        self.assertEqual(
            result["counts"]["evidence_admitted_records"],
            sum(1 for r in records if r["verification_level"] in X.L3_PLUS))
        self.assertEqual(result["counts"]["evidence_admitted_records"], 6)
        self.assertEqual(result["levels"],
                         {"l3": 3, "l4": 1, "l5": 1, "l6": 1})

    def test_three_populations_cannot_be_conflated(self):
        # 10 distinct proof runs, 5 admitted L3+ records, 6 ledger rows carrying
        # an artefact: three different numbers, so an implementation that reads
        # one population for another key fails here. The attempt partition
        # (5 + 3 + 2 = 10) is deliberately unrelated to the record count.
        runs = ([_run(f"s{i}", "violation_observed", 0) for i in range(5)]
                + [_run(f"b{i}", "blocked", 1) for i in range(3)]
                + [_run(f"f{i}", "test_failed", 1) for i in range(2)])
        ledger = [_candidate(f"c{i}") for i in range(6)]
        records = ([_record("L3", "c0"), _record("L3", "c1"), _record("L3", "c2"),
                    _record("L4", "c3"), _record("L5", "c4"), _record("L0", "c5")])
        result = _accounting(runs, ledger, records)
        self.assertEqual(result["errors"], [])
        counts = result["counts"]
        self.assertEqual(counts["execution_attempts"], 10)
        self.assertEqual(counts["evidence_admitted_records"], 5)
        self.assertEqual(counts["candidate_artefacts"], 6)
        self.assertEqual(
            counts["successful_executions"] + counts["failed_executions"]
            + counts["blocked_executions"], counts["execution_attempts"])
        # The L3+ count is independent of the attempt partition: it is neither
        # the number of runs nor the number of artefact-carrying candidates.
        self.assertNotEqual(counts["evidence_admitted_records"],
                            counts["execution_attempts"])
        self.assertNotEqual(counts["evidence_admitted_records"],
                            counts["candidate_artefacts"])
        self.assertNotEqual(counts["evidence_admitted_records"],
                            counts["successful_executions"]
                            + counts["failed_executions"]
                            + counts["blocked_executions"])

    def test_definitions_cover_every_count(self):
        result = _accounting([], records=[_record("L3", "a"), _record("L5", "b")])
        self.assertEqual(set(result["definitions"]), set(result["counts"]))
        self.assertIn("NOT a count of reproduced",
                      result["definitions"]["evidence_admitted_records"])
        self.assertIn("counts candidates, not admitted records",
                      result["definitions"]["candidate_artefacts"])
        self.assertIn("counts runs, not records",
                      result["definitions"]["execution_attempts"])

    def test_shipped_layer_five_l5_zero_l6_at_127(self):
        ledger, records = _shipped_layers()
        result = X.run_accounting(ROOT, ledger, records)
        counts = result["counts"]
        self.assertEqual(counts["evidence_admitted_records"], 127)
        self.assertEqual(counts["execution_attempts"], 18)
        self.assertNotEqual(counts["evidence_admitted_records"],
                            counts["execution_attempts"])
        self.assertEqual(sorted(r["finding_id"] for r in records
                                if r["verification_level"] == "L5"),
                         sorted(SHIPPED_L5_IDS))
        self.assertEqual([r["finding_id"] for r in records
                          if r["verification_level"] == "L6"], [])
        self.assertEqual(result["levels"],
                         {"l3": 115, "l4": 7, "l5": 5, "l6": 0})

    def test_shipped_manifest_publishes_definitions_and_note(self):
        for rel in ("derived_v3/manifest.json", "reports/v3/dataset_summary.json"):
            manifest = json.loads((ROOT / rel).read_text(encoding="utf-8"))
            published = manifest.get("run_accounting_definitions") or {}
            self.assertEqual(set(published), ACCOUNTING_KEYS, rel)
            self.assertIn("NOT a count of reproduced vulnerabilities",
                          published["evidence_admitted_records"], rel)
            note = manifest.get("experimental_runs_note") or ""
            self.assertIn("5 records reproduce a claimed violation (L5)", note,
                          rel)
            self.assertIn("0 are two-revision verified (L6)", note, rel)
            self.assertIn("18 distinct proof runs", note, rel)
            self.assertIn("127 records carry an admitted execution artefact",
                          note, rel)


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