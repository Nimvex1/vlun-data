"""A recorded violation must say which assertion broke.

`forge test --json` reports a failure reason on the test entry; the human
`[FAIL: …]` line only exists without `--json`. The experiment recorder used to
read only the human line, so every JSON run stored `reason: null` and an
observed violation looked identical to a test that failed for an unrelated
reason. These tests pin the fixed extraction, and the VLUN-Prove ladder against
samples where the reason is missing, unrelated, or correct.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import experiments as ex  # noqa: E402
import prove_grader as G  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures" / "broken" / "prove"

JSON_SAMPLE = (
    '{"test/Exploits.t.sol:ExploitTest":{"test_results":'
    '{"test_DisableModule_Exploit":{"status":"Failure",'
    '"reason":"next call did not revert as expected"}}}}')
HUMAN_SAMPLE = ("Ran 1 test for test/Exploits.t.sol:ExploitTest\n"
                "[FAIL: next call did not revert as expected] "
                "test_DisableModule_Exploit() (time: 12ms)\n")


def _fx(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class ReasonExtraction(unittest.TestCase):
    def test_json_entry_reason_is_kept(self):
        entry = {"status": "Failure", "reason": "next call did not revert as expected"}
        self.assertEqual(
            ex.per_test_reason(entry, "test_X()", ""),
            "next call did not revert as expected")

    def test_items_reason_is_used_when_the_flat_field_is_absent(self):
        entry = {"status": "Failure", "items": {"reason": "panic: up underflow"}}
        self.assertEqual(ex.per_test_reason(entry, "test_X()", ""), "panic: up underflow")

    def test_human_output_still_works_as_a_fallback(self):
        self.assertEqual(
            ex.per_test_reason({"status": "Failure"}, "test_DisableModule_Exploit()",
                               HUMAN_SAMPLE),
            "next call did not revert as expected")

    def test_no_reason_is_invented_when_none_exists(self):
        self.assertIsNone(ex.per_test_reason({"status": "Failure"}, "test_X()",
                                             "nothing useful here"))

    def test_parse_forge_output_reads_the_json_reason(self):
        status, signals = G.parse_forge_output(JSON_SAMPLE)
        self.assertEqual(status, {"test_DisableModule_Exploit()": "Failure"})
        self.assertEqual(signals[0]["forge_reason"],
                         "next call did not revert as expected")
        self.assertFalse(signals[0]["test"].endswith("()()"),
                         "test names must not gain a second pair of parentheses")

    def test_parse_forge_output_on_human_log_keeps_the_reason(self):
        status, signals = G.parse_forge_output(HUMAN_SAMPLE)
        self.assertEqual(status["test_DisableModule_Exploit()"], "Failure")
        self.assertEqual(signals[0]["forge_reason"],
                         "next call did not revert as expected")

    def test_unparseable_log_yields_nothing_rather_than_a_guess(self):
        status, signals = G.parse_forge_output("compiler error: expected }")
        self.assertEqual(status, {})
        self.assertEqual(signals, [])


class LadderRefusesUnrelatedFailures(unittest.TestCase):
    def test_broken_fixture_compile_failure_cannot_reach_impact(self):
        fx = _fx("compile_failure_promoted.json")
        v = G.stage_ladder(fx["submission"], fx["vulnerable"], fx["fixed"], fx["expected"])
        self.assertEqual(v["stage_reached"], "generated")

    def test_a_failure_without_a_recorded_assertion_stops_at_executes(self):
        expected = {"failing_tests": ["test_X()"]}
        v = G.stage_ladder({"files": {"a.t.sol": "// x"}},
                           {"build_rc": 0, "dependency_ok": True, "ran_tests": True,
                            "per_test_status": {"test_X()": "Failure"},
                            "signals": [{"test": "test_X()", "forge_reason": None,
                                         "assertion_messages": []}]},
                           {"build_rc": 0, "dependency_ok": True, "ran_tests": True,
                            "per_test_status": {"test_X()": "Success"}, "signals": []},
                           expected)
        self.assertFalse(v["stages"]["impact_reproduced"])
        self.assertEqual(v["stage_reached"], "executes")

    def test_the_same_bytes_must_be_blocked_on_the_second_revision(self):
        good = {"build_rc": 0, "dependency_ok": True, "ran_tests": True,
                "per_test_status": {"test_X()": "Failure"},
                "signals": [{"test": "test_X()", "forge_reason": None,
                             "assertion_messages": ["a == b not satisfied"]}]}
        still_broken = dict(good)
        v = G.stage_ladder({"files": {"a.t.sol": "// x"}}, good, still_broken,
                           {"failing_tests": ["test_X()"]})
        self.assertTrue(v["stages"]["impact_reproduced"])
        self.assertFalse(v["stages"]["patch_verified"])


if __name__ == "__main__":
    unittest.main()
