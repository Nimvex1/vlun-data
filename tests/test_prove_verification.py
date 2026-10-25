"""VLUN-Prove: a fully effective patch needs a third piece of evidence.

Blocking the exploit is not the same as fixing the defect: a patch that deletes
or disables the feature also blocks the exploit. The grader therefore asks for a
recorded behaviour-preservation run on the fixed revision, compared against a
vulnerable-revision baseline, and refuses to call a task fully verified without
it. These tests are the negative controls: each one must be refused.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import prove_grader as G  # noqa: E402

INTERFACE = ROOT / "reports" / "prove_split_interface.json"
HEX = "a" * 64
VULN_REV = "b" * 40
FIXED_REV = "c" * 40


def regression(**overrides) -> dict:
    record = {
        "baseline": {"revision": VULN_REV, "test_command": "forge test",
                     "test_artifact_sha256": HEX, "failures": ["test_PreExisting()"]},
        "fixed": {"revision": FIXED_REV, "test_command": "forge test",
                  "test_artifact_sha256": HEX, "failures": ["test_PreExisting()"],
                  "feature_present": True, "disabled": False, "removed_symbols": []},
        "positive_path": [{"name": "test_TransferStillWorks()", "status": "Success"}],
    }
    record.update(overrides)
    return record


class BehaviourPreservation(unittest.TestCase):
    def test_a_complete_record_is_accepted(self):
        ok, why = G.behaviour_verdict(regression(), {"fixed_revision": FIXED_REV})
        self.assertTrue(ok, why)

    def test_no_record_is_not_full_verification(self):
        ok, why = G.behaviour_verdict(None)
        self.assertFalse(ok)
        self.assertIn("no behaviour-preservation run recorded", why)

    def test_a_missing_baseline_is_refused(self):
        record = regression()
        record.pop("baseline")
        ok, why = G.behaviour_verdict(record, {"fixed_revision": FIXED_REV})
        self.assertFalse(ok)
        self.assertIn("baseline is missing", why)

    def test_an_absent_failures_list_is_not_a_green_baseline(self):
        record = regression()
        record["baseline"].pop("failures")
        ok, why = G.behaviour_verdict(record, {"fixed_revision": FIXED_REV})
        self.assertFalse(ok)
        self.assertIn("failures list was not recorded", why)

    def test_a_new_failure_on_the_fixed_revision_is_refused(self):
        record = regression()
        record["fixed"]["failures"] = ["test_PreExisting()", "test_Transfer()"]
        ok, why = G.behaviour_verdict(record, {"fixed_revision": FIXED_REV})
        self.assertFalse(ok)
        self.assertIn("introduced regression failures", why)
        self.assertIn("test_Transfer()", why)

    def test_a_patch_that_deletes_the_feature_is_refused(self):
        record = regression()
        record["fixed"]["feature_present"] = False
        ok, why = G.behaviour_verdict(record, {"fixed_revision": FIXED_REV})
        self.assertFalse(ok)
        self.assertIn("deleting the feature is not a fix", why)

    def test_a_disabled_feature_is_refused(self):
        record = regression()
        record["fixed"]["disabled"] = True
        ok, why = G.behaviour_verdict(record, {"fixed_revision": FIXED_REV})
        self.assertFalse(ok)
        self.assertIn("disabled", why)

    def test_removed_symbols_are_refused(self):
        record = regression()
        record["fixed"]["removed_symbols"] = ["transfer()"]
        ok, why = G.behaviour_verdict(record, {"fixed_revision": FIXED_REV})
        self.assertFalse(ok)
        self.assertIn("removed the feature's symbols", why)

    def test_a_failed_positive_path_assertion_is_refused(self):
        record = regression()
        record["positive_path"] = [{"name": "test_TransferStillWorks()",
                                    "status": "Failure"}]
        ok, why = G.behaviour_verdict(record, {"fixed_revision": FIXED_REV})
        self.assertFalse(ok)
        self.assertIn("positive-path assertions did not pass", why)

    def test_no_positive_path_assertion_is_refused(self):
        record = regression()
        record["positive_path"] = []
        ok, why = G.behaviour_verdict(record, {"fixed_revision": FIXED_REV})
        self.assertFalse(ok)
        self.assertIn("no targeted positive-path assertion", why)

    def test_an_unpinned_test_artifact_is_refused(self):
        record = regression()
        record["fixed"]["test_artifact_sha256"] = "not-a-hash"
        ok, why = G.behaviour_verdict(record, {"fixed_revision": FIXED_REV})
        self.assertFalse(ok)
        self.assertIn("hash-pinned", why)

    def test_two_revisions_running_different_artifacts_are_refused(self):
        record = regression()
        record["fixed"]["test_artifact_sha256"] = "d" * 64
        ok, why = G.behaviour_verdict(record, {"fixed_revision": FIXED_REV})
        self.assertFalse(ok)
        self.assertIn("same hash-pinned test artifact", why)

    def test_a_regression_run_at_another_revision_is_refused(self):
        record = regression()
        record["fixed"]["revision"] = "e" * 40
        ok, why = G.behaviour_verdict(record, {"fixed_revision": FIXED_REV})
        self.assertFalse(ok)
        self.assertIn("not the pinned fix", why)

    def test_a_submission_only_command_is_not_the_project_suite(self):
        record = regression()
        record["fixed"]["test_command"] = "forge test --match-path test/vlun_poc/*"
        ok, why = G.behaviour_verdict(record, {"fixed_revision": FIXED_REV})
        self.assertFalse(ok)
        self.assertIn("not the project's existing suite", why)


class LadderStopsWithoutBehaviourEvidence(unittest.TestCase):
    def run_ladder(self, regression_record):
        vulnerable = {"build_rc": 0, "dependency_ok": True, "ran_tests": True,
                      "per_test_status": {"test_Exploit()": "Failure"},
                      "signals": [{"test": "test_Exploit()", "forge_reason": None,
                                   "assertion_messages": ["Error: a == b not satisfied"]}]}
        fixed = {"build_rc": 0, "dependency_ok": True, "ran_tests": True,
                 "per_test_status": {"test_Exploit()": "Success"}, "signals": []}
        expected = {"failing_tests": ["test_Exploit()"],
                    "signals": [{"test": "test_Exploit()", "forge_reason": None,
                                 "assertion_messages": ["Error: a == b not satisfied"]}],
                    "fixed_revision": FIXED_REV}
        return G.stage_ladder({"files": {"a.t.sol": "contract X"}}, vulnerable, fixed,
                              expected, regression_record)

    def test_without_regression_evidence_the_task_is_not_fully_verified(self):
        verdict = self.run_ladder(None)
        self.assertEqual(verdict["stage_reached"], "patch_verified")
        self.assertFalse(verdict["stages"]["behaviour_preserved"])
        self.assertFalse(verdict["fully_verified"])

    def test_with_regression_evidence_the_task_is_fully_verified(self):
        verdict = self.run_ladder(regression())
        self.assertEqual(verdict["stage_reached"], "behaviour_preserved")
        self.assertTrue(verdict["stages"]["behaviour_preserved"])
        self.assertTrue(verdict["fully_verified"])


class PublishedCounts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.interface = json.loads(INTERFACE.read_text(encoding="utf-8"))

    def test_the_four_counts_are_reported_separately(self):
        counts = self.interface["pool"]["counts"]
        for key in ("candidate_ledger_rows", "technically_qualified_experiments",
                    "gradable_tasks", "release_eligible_tasks"):
            self.assertIn(key, counts)
            self.assertIsInstance(counts[key], int)

    def test_the_counts_cannot_run_upwards(self):
        counts = self.interface["pool"]["counts"]
        self.assertLessEqual(counts["release_eligible_tasks"], counts["gradable_tasks"])
        self.assertLessEqual(counts["gradable_tasks"],
                             counts["technically_qualified_experiments"])
        self.assertLessEqual(counts["technically_qualified_experiments"],
                             counts["candidate_ledger_rows"])

    def test_the_published_headline_is_not_the_ledger_count(self):
        pool = self.interface["pool"]
        counts = pool["counts"]
        self.assertEqual(pool["qualified_pool_size"], counts["gradable_tasks"])
        self.assertNotEqual(pool["qualified_pool_size"], counts["candidate_ledger_rows"])
        self.assertEqual(pool["ledger"]["ledger_rows"], counts["candidate_ledger_rows"])

    def test_no_task_claims_to_be_fully_verified_without_the_regression_evidence(self):
        for task in self.interface["tasks"]:
            reached = task.get("self_check_stage_reached")
            self.assertNotEqual(reached, "behaviour_preserved", task.get("task_id"))


if __name__ == "__main__":
    unittest.main()
