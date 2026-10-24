"""The Prove ledger is the control that keeps `qualified` honest, so its rules are tested
against rows that must fail - not only against the rows that happen to pass."""
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import build_prove_ledger as bl  # noqa: E402

QUALIFIED = {
    "candidate_id": "ok::1", "candidate_stage": "qualified", "repository": "r",
    "vulnerable_commit": "a", "fixed_commit": "b", "test_sha256": "aa",
    "test_sha256_fixed_side": "aa", "vulnerable_artifact": "x", "fixed_artifact": "y",
    "toolchain": "forge 1.8.3", "stage_decision": "patch_verified",
    "licence_code": "MIT", "rights_reference": "work/prove_candidates/web_ledger.jsonl",
}


class TestQualificationRules(unittest.TestCase):
    def test_a_complete_identical_test_row_is_accepted(self):
        self.assertEqual(bl.validate([dict(QUALIFIED)]), [])

    def test_differing_test_bytes_are_refused(self):
        row = dict(QUALIFIED, test_sha256_fixed_side="zz")
        problems = bl.validate([row])
        self.assertTrue(any("test bytes differ" in p for p in problems), problems)

    def test_each_missing_admission_field_is_named(self):
        for field in bl.QUALIFICATION_FIELDS:
            row = dict(QUALIFIED)
            row.pop(field)
            problems = bl.validate([row])
            self.assertTrue(any(field in p for p in problems), (field, problems))

    def test_a_non_verification_stage_decision_cannot_qualify(self):
        row = dict(QUALIFIED, stage_decision="executes")
        self.assertTrue(any("stage_decision" in p for p in bl.validate([row])))

    def test_blocked_rows_keep_their_blocker(self):
        row = {"candidate_id": "b::1", "candidate_stage": "blocked"}
        self.assertTrue(any("requires a recorded blocker" in p
                            for p in bl.validate([row])))
        self.assertEqual(bl.validate([dict(row, blocker="fixture absent at pin")]), [])

    def test_a_qualified_row_without_a_rights_position_is_refused(self):
        for field in ("licence_code", "rights_reference"):
            row = dict(QUALIFIED)
            row.pop(field)
            problems = bl.validate([row])
            self.assertTrue(any("rights position" in p for p in problems), (field, problems))

    def test_withheld_rights_is_an_acceptable_position(self):
        row = dict(QUALIFIED)
        row.pop("licence_code")
        row.pop("rights_reference")
        row["rights_status"] = "withheld_pending_permission"
        self.assertEqual(bl.validate([row]), [])

    def test_unknown_stage_is_refused(self):
        row = {"candidate_id": "u::1", "candidate_stage": "almost_qualified"}
        self.assertTrue(bl.validate([row]))


class TestLedgerNormalisation(unittest.TestCase):
    def test_blockers_list_becomes_a_single_blocker(self):
        row = bl.normalize({"candidate_id": "n::1", "candidate_stage": "blocked",
                            "blockers": ["compile error", "no fixture"]}, "test")
        self.assertEqual(row["blocker"], "compile error; no fixture")

    def test_framework_notes_fold_without_losing_the_original(self):
        row = bl.normalize({"candidate_id": "n::2", "candidate_stage": "candidate",
                            "framework": "sui-move (sui 1.48.2 and 1.6.3 recorded)"}, "test")
        self.assertEqual(row["framework"], "sui-move")
        self.assertIn("1.48.2", row["framework_recorded"])
        self.assertEqual(bl.framework_key("hardhat+foundry"), "foundry+hardhat")
        self.assertEqual(bl.framework_key("unknown (no readable diff)"), "unknown")
        for value in ("foundry", "hardhat", "cairo", "sui-move", "other", "unknown"):
            self.assertIn(bl.framework_key(value), bl.FRAMEWORKS)


class TestPublishedLedger(unittest.TestCase):
    def test_report_counts_equal_the_ledger_file(self):
        rows = bl._load(bl.LEDGER)
        stats = json.loads(bl.STATS_JSON.read_text(encoding="utf-8"))
        self.assertEqual(stats["counts"]["candidate_rows"], len(rows))
        by_stage = {}
        for row in rows:
            by_stage[row["candidate_stage"]] = by_stage.get(row["candidate_stage"], 0) + 1
        self.assertEqual(stats["counts"]["by_stage"], by_stage)
        self.assertEqual(stats["counts"]["distinct_repositories"],
                         len({r["repository"] for r in rows if r.get("repository")}))
        self.assertEqual(stats["invariants_violated"], [])

    def test_a_qualified_row_in_the_shipped_ledger_satisfies_the_invariant(self):
        for row in bl._load(bl.LEDGER):
            if row.get("candidate_stage") != "qualified":
                continue
            self.assertEqual(row["test_sha256"], row["test_sha256_fixed_side"], row["candidate_id"])
            self.assertTrue(row.get("vulnerable_commit") and row.get("fixed_commit"))
            self.assertTrue(row.get("vulnerable_artifact") and row.get("fixed_artifact"))

    def test_failed_attempts_are_kept_not_deleted(self):
        rows = bl._load(bl.LEDGER)
        refused = [r for r in rows if r["candidate_stage"] in ("blocked", "rejected_with_reason",
                                                              "candidate")]
        self.assertTrue(refused, "the ledger contains no failures: attempts were likely deleted")
        self.assertTrue(all(r.get("blocker") or r["candidate_stage"] == "candidate"
                            for r in refused))


if __name__ == "__main__":
    unittest.main()
