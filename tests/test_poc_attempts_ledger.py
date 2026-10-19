"""The attempt ledger is where the old "forge ran means reproduced" mistake dies.

Rules under test (see scripts/rerun_v1_pocs.py::validate_ledger_rows):

  * a compiler success is L3 and nothing more;
  * execution alone is L4 - it does not establish L5;
  * L5 requires the record's own assertion to be named and to have held;
  * a compile failure carries no level at all;
  * unique vulnerability records and total runs are different numbers, so a
    rerun may not reuse an attempt_id and pass as another finding;
  * every recorded artefact hash must still match the bytes on disk.

Broken fixtures under tests/fixtures/broken/poc_attempts/ are required to fail.

Run with: python -m unittest tests.test_poc_attempts_ledger
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import rerun_v1_pocs as rr  # noqa: E402

LEDGER = ROOT / "reports" / "poc_attempts.jsonl"
FIXTURES = ROOT / "tests" / "fixtures" / "broken" / "poc_attempts"


def load_rows(p: Path) -> list[dict]:
    return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines()
            if l.strip()]


class TestCommittedLedger(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = load_rows(LEDGER) if LEDGER.exists() else []

    def test_ledger_exists_and_is_not_empty(self):
        self.assertTrue(LEDGER.exists(), f"{LEDGER} missing: no attempt was recorded")
        self.assertTrue(self.rows, "the ledger holds no attempts")

    def test_committed_ledger_validates(self):
        errs = rr.validate_ledger_rows(self.rows)
        self.assertEqual(errs, [], "ledger breaches: " + "; ".join(errs[:6]))

    def test_recorded_hashes_match_disk(self):
        """Immutable output: the sha256 in the ledger is the bytes we shipped."""
        errs = rr.validate_ledger_rows(self.rows, check_paths=True)
        hash_errs = [e for e in errs if "hashes to the recorded" in e
                     or "recorded artefact" in e or "no result.json" in e]
        self.assertEqual(hash_errs, [], "; ".join(hash_errs[:6]))

    def test_outcomes_use_the_closed_vocabulary(self):
        for r in self.rows:
            self.assertIn(r["outcome"], rr.OUTCOMES,
                          f"{r['attempt_id']} has an invented outcome")

    def test_unique_records_and_total_runs_are_separate(self):
        unique = len({r["finding_id"] for r in self.rows})
        total = len(self.rows)
        self.assertLessEqual(unique, total)
        doc = json.loads((ROOT / "reports" / "poc_execution_density.json")
                         .read_text(encoding="utf-8"))
        self.assertEqual(doc["attempts"]["unique_vulnerability_records_attempted"],
                         unique)
        self.assertEqual(doc["attempts"]["total_runs_recorded"], total)
        self.assertNotEqual(
            doc["attempts"]["unique_vulnerability_records_attempted"],
            doc["attempts"]["distinct_sandboxed_invocations"],
            "if these ever coincide the report has stopped distinguishing a record "
            "from a run; verify by hand before trusting either number")

    def test_density_counts_follow_from_the_ledger(self):
        doc = json.loads((ROOT / "reports" / "poc_execution_density.json")
                         .read_text(encoding="utf-8"))
        # the report lists every outcome class, including the empty ones
        outcomes = {k: 0 for k in rr.OUTCOMES}
        for r in self.rows:
            outcomes[r["outcome"]] = outcomes.get(r["outcome"], 0) + 1
        self.assertEqual(doc["outcomes"], dict(sorted(outcomes.items())))

    def test_no_run_above_L3_without_a_successful_compile(self):
        for r in self.rows:
            lv = r.get("evidence_level_supported")
            if lv in ("L4", "L5", "L6"):
                self.assertIn(r["outcome"], ("executed_without_impact",
                                             "claim_reproduced"),
                              f"{r['attempt_id']}: {lv} without execution")

    def test_claim_reproduced_entries_name_an_assertion(self):
        for r in self.rows:
            if r["outcome"] == "claim_reproduced":
                at = r.get("assertion_tested") or {}
                self.assertTrue(at.get("assertions") or at.get("declared_test_functions"),
                                f"{r['attempt_id']}: reproduction without an assertion")

    def test_blocked_entries_name_a_blocker(self):
        for r in self.rows:
            if r["outcome"] == "blocked":
                self.assertIn(r.get("blocker_class"), rr.QUEUE_BLOCKERS,
                              f"{r['attempt_id']}: blocked without a blocker class")


class TestBrokenFixturesFail(unittest.TestCase):
    def _rows(self, name: str) -> list[dict]:
        p = FIXTURES / name
        self.assertTrue(p.exists(), f"broken fixture {name} is missing")
        return load_rows(p)

    def test_claim_reproduced_without_assertion_is_rejected(self):
        errs = rr.validate_ledger_rows(self._rows("claim_reproduced_without_assertion.jsonl"))
        self.assertTrue(any("without naming the assertion" in e for e in errs),
                        f"validator accepted an unasserted reproduction: {errs}")

    def test_compile_failure_promoted_to_L4_is_rejected(self):
        errs = rr.validate_ledger_rows(self._rows("compile_failure_promoted_to_L4.jsonl"))
        self.assertTrue(any("cannot support L3 or above" in e for e in errs),
                        f"validator accepted a promoted compile failure: {errs}")

    def test_duplicate_attempt_id_is_rejected(self):
        errs = rr.validate_ledger_rows(self._rows("duplicate_attempt_id.jsonl"))
        self.assertTrue(any("a rerun is not a" in e for e in errs),
                        f"validator accepted a rerun counted as a new record: {errs}")

    def test_blocked_without_blocker_class_is_rejected(self):
        errs = rr.validate_ledger_rows(self._rows("blocked_without_blocker_class.jsonl"))
        self.assertTrue(any("blocked attempt has no blocker class" in e for e in errs),
                        f"validator accepted an unexplained block: {errs}")

    def test_nothing_ran_but_claimed_reproduced_is_rejected(self):
        errs = rr.validate_ledger_rows(self._rows("blocked_without_blocker_class.jsonl"))
        self.assertTrue(any("nothing ran but the outcome" in e for e in errs),
                        f"validator accepted a claim with no run: {errs}")

    def test_fixtures_fail_only_for_their_intended_reason(self):
        for name, needles in (
                ("claim_reproduced_without_assertion.jsonl",
                 ("without naming the assertion",)),
                # a promoted compile failure is doubly wrong: it claims a level it
                # never earned and it claims an execution that never happened, so
                # both rules are expected to fire.
                ("compile_failure_promoted_to_L4.jsonl",
                 ("cannot support L3 or above", "requires an executed run")),
                ("duplicate_attempt_id.jsonl", ("a rerun is not a",))):
            errs = rr.validate_ledger_rows(self._rows(name))
            extra = [e for e in errs if not any(n in e for n in needles)]
            self.assertEqual(extra, [],
                             f"{name} also breaks unrelated rules: {extra}")


if __name__ == "__main__":
    unittest.main()
