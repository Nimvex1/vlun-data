"""VLUN-Prove: the ladder, the isolation, and the commitment must all hold.

A prove task is only worth what its grader is strict about. These tests assert
the rules directly, and they fail on deliberately broken fixtures: a task list
that carries the hidden fixed revision, a run that stops at a compile error but
is credited as an attempted proof, an answer key whose bytes moved after the
commitment was published, and a private split written inside the repo.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_prove_split as B  # noqa: E402
import prove_grader as G  # noqa: E402

INTERFACE = ROOT / "reports" / "prove_split_interface.json"
FIXTURES = ROOT / "tests" / "fixtures" / "broken" / "prove"


def _fx(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def run(*, build_rc=0, dependency_ok=True, ran=True, status=None, signals=None) -> dict:
    return {"build_rc": build_rc, "dependency_ok": dependency_ok, "ran_tests": ran,
            "per_test_status": status or {}, "signals": signals or []}


EXPECTED = {"failing_tests": ["test_Exploit()"],
            "signals": [{"test": "test_Exploit()", "forge_reason": None,
                         "assertion_messages": ["Error: a == b not satisfied"]}]}


class StageLadderRules(unittest.TestCase):
    def test_empty_submission_never_reaches_generated(self):
        v = G.stage_ladder({"files": {}}, run(), run(), EXPECTED)
        self.assertFalse(v["stages"]["generated"])
        self.assertEqual(v["stage_reached"], "none")

    def test_compile_failure_stops_the_ladder_and_credits_nothing_higher(self):
        v = G.stage_ladder({"files": {"a.t.sol": "contract X"}},
                           run(build_rc=1), run(), EXPECTED)
        self.assertTrue(v["stages"]["generated"])
        self.assertFalse(v["stages"]["compiles"])
        for stage in ("executes", "impact_reproduced", "patch_verified"):
            self.assertFalse(v["stages"][stage], stage)
        self.assertEqual(v["stage_reached"], "generated")

    def test_dependency_failure_is_not_treated_as_a_run(self):
        v = G.stage_ladder({"files": {"a.t.sol": "contract X"}},
                           run(dependency_ok=False, build_rc=None), run(), EXPECTED)
        self.assertFalse(v["stages"]["compiles"])
        self.assertIn("dependenc", v["reasons"]["compiles"].lower())

    def test_a_test_that_passes_on_the_vulnerable_revision_proves_no_impact(self):
        v = G.stage_ladder({"files": {"a.t.sol": "contract X"}},
                           run(status={"test_Exploit()": "Success"}),
                           run(status={"test_Exploit()": "Success"}), EXPECTED)
        self.assertTrue(v["stages"]["executes"])
        self.assertFalse(v["stages"]["impact_reproduced"])

    def test_failure_for_an_unrelated_reason_is_not_impact(self):
        v = G.stage_ladder(
            {"files": {"a.t.sol": "contract X"}},
            run(status={"test_Exploit()": "Failure"},
                signals=[{"test": "test_Exploit()", "forge_reason":
                          "out of gas (E2523)", "assertion_messages": []}]),
            run(), EXPECTED)
        self.assertFalse(v["stages"]["impact_reproduced"],
                         "a failing exit code is not a demonstrated violation")

    def test_failure_with_no_recorded_assertion_is_not_impact(self):
        v = G.stage_ladder(
            {"files": {"a.t.sol": "contract X"}},
            run(status={"test_Exploit()": "Failure"},
                signals=[{"test": "test_Exploit()", "forge_reason": None,
                          "assertion_messages": []}]),
            run(), EXPECTED)
        self.assertTrue(v["stages"]["executes"])
        self.assertFalse(v["stages"]["impact_reproduced"])
        self.assertIn("no assertion", v["reasons"]["impact_reproduced"])

    def test_wrong_test_failing_is_not_the_claimed_violation(self):
        v = G.stage_ladder(
            {"files": {"a.t.sol": "contract X"}},
            run(status={"test_Other()": "Failure"},
                signals=[{"test": "test_Other()", "forge_reason": None,
                          "assertion_messages": ["boom"]}]),
            run(), EXPECTED)
        self.assertFalse(v["stages"]["impact_reproduced"])

    def test_the_full_ladder_needs_the_assertion_and_the_blocked_patch(self):
        good = run(status={"test_Exploit()": "Failure"},
                   signals=[{"test": "test_Exploit()", "forge_reason": None,
                              "assertion_messages": ["Error: a == b not satisfied"]}])
        blocked = run(status={"test_Exploit()": "Success"})
        v = G.stage_ladder({"files": {"a.t.sol": "contract X"}}, good, blocked, EXPECTED)
        self.assertEqual(v["stage_reached"], "patch_verified")
        self.assertTrue(all(v["stages"][s] for s in G.STAGES))

    def test_a_patch_that_does_not_block_stops_at_impact(self):
        good = run(status={"test_Exploit()": "Failure"},
                   signals=[{"test": "test_Exploit()", "forge_reason": None,
                              "assertion_messages": ["Error: a == b not satisfied"]}])
        v = G.stage_ladder({"files": {"a.t.sol": "contract X"}}, good, good, EXPECTED)
        self.assertTrue(v["stages"]["impact_reproduced"])
        self.assertFalse(v["stages"]["patch_verified"])
        self.assertEqual(v["stage_reached"], "impact_reproduced")

    def test_broken_fixture_a_run_promoted_past_a_compile_failure(self):
        fx = _fx("compile_failure_promoted.json")
        v = G.stage_ladder(fx["submission"], fx["vulnerable"], fx["fixed"], fx["expected"])
        self.assertFalse(v["stages"]["compiles"])
        self.assertFalse(v["stages"]["impact_reproduced"])
        self.assertNotEqual(v["stage_reached"], "patch_verified")


class IsolationRules(unittest.TestCase):
    def test_the_key_refuses_to_live_inside_the_repository(self):
        with self.assertRaises(SystemExit):
            B.private_home(ROOT / "leaked_key")
        with self.assertRaises(SystemExit):
            G.read_key(ROOT, "anything")

    def test_public_task_list_may_not_carry_the_fixed_revision(self):
        fx = _fx("leaky_interface_tasks.json")
        bad = B.public_leak_check(fx)
        self.assertTrue(any("fixed_commit" in b for b in bad), bad)
        self.assertTrue(any("40-hex revision" in b for b in bad), bad)

    def test_the_published_interface_passes_its_own_guard(self):
        interface = json.loads(INTERFACE.read_text(encoding="utf-8"))
        self.assertEqual(B.public_leak_check(interface), [])

    def test_no_public_field_names_a_hidden_test_or_assertion(self):
        interface = json.loads(INTERFACE.read_text(encoding="utf-8"))
        blob = json.dumps(interface["tasks"], ensure_ascii=False)
        for forbidden in ("test_MaliciousSeaportTip", "test_VlunEip712",
                          "test_DisableModule", "expected_assertion", "match_test"):
            self.assertNotIn(forbidden, blob)

    def test_the_commitment_pins_the_private_key(self):
        interface = json.loads(INTERFACE.read_text(encoding="utf-8"))
        files = interface["private_commitment"]["files"]
        self.assertTrue(files, "the interface must publish at least one pinned private file")
        for name, meta in files.items():
            self.assertRegex(meta["sha256"], r"^[0-9a-f]{64}$")
            self.assertGreater(meta["bytes"], 0)
            self.assertNotIn(str(ROOT), json.dumps(interface["private_commitment"]))

    def test_commitment_verification_fails_when_the_key_moves(self):
        import shutil
        import tempfile
        real = Path.home() / "vlun-private" / "vlun_prove"
        if not real.exists():
            self.skipTest("no private split on this machine")
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            shutil.copytree(real, home / "vlun_prove")
            B.verified_private_commitment(home)          # green before the tamper
            key = home / "vlun_prove" / "prove_tasks_private.jsonl"
            key.write_bytes(key.read_bytes() + b'{"task_id": "tamper"}\n')
            with self.assertRaises(SystemExit) as ctx:
                B.verified_private_commitment(home)
            self.assertIn("bytes changed", str(ctx.exception))
        self.assertTrue(real.exists(), "the test must not touch the real split")


class InterfaceHonesty(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.i = json.loads(INTERFACE.read_text(encoding="utf-8"))

    def test_the_pool_reports_its_real_size_not_the_target(self):
        self.assertFalse(self.i["pool"]["target_met"])
        self.assertEqual(self.i["pool"]["tasks_with_two_revisions_executed"],
                         len(self.i["tasks"]))
        self.assertIn("bounded by", self.i["pool"]["why_smaller"])

    def test_the_self_check_is_labelled_as_not_a_model_result(self):
        sc = self.i["grader_self_check"]
        self.assertTrue(sc["is_not_a_model_result"])
        self.assertGreater(sc["tasks_self_checked"], 0)
        self.assertLessEqual(sc["stage_reached_distribution"].get("patch_verified", 0),
                             sc["tasks_self_checked"])

    def test_self_check_covers_only_runs_it_could_replay(self):
        checked = [t for t in self.i["tasks"] if t["self_check_stage_reached"]]
        self.assertEqual(len(checked), self.i["grader_self_check"]["tasks_self_checked"])
        for t in checked:
            self.assertIn(t["self_check_stage_reached"], G.STAGES)
        unchecked = [t for t in self.i["tasks"] if not t["self_check_stage_reached"]]
        self.assertTrue(unchecked,
                        "a runner the grader cannot execute must stay visibly unchecked")
        for t in unchecked:
            self.assertFalse(t["gradable_by_the_published_grader"])
        # no task may claim patch_verified without an assertion having been seen
        signals = json.loads(
            (Path.home() / "vlun-private" / "vlun_prove" / "grader_self_check.json")
            .read_text(encoding="utf-8")) if (Path.home() / "vlun-private" / "vlun_prove"
                                              / "grader_self_check.json").exists() else []
        for row in signals:
            if row["stage_reached"] == "patch_verified":
                self.assertIn("impact_reproduced", row["reasons"])

    def test_the_leakage_audit_never_claims_contamination_proof(self):
        self.assertTrue(self.i["leakage_audit"]["not_contamination_proof"])
        blob = INTERFACE.read_text(encoding="utf-8")
        # the word may only appear negated: "not ... contamination-proof"
        for line in [ln for ln in blob.splitlines() if "contamination" in ln.lower()]:
            self.assertTrue(("not_contamination_proof" in line
                             or "not and must not be described as" in line
                             or '"not contamination-proof"' in line
                             or "is not" in line.lower() or "not_" in line.lower()),
                            f"un-negated contamination claim: {line.strip()[:120]}")

    def test_unsupported_runners_are_marked_not_gradable_rather_than_dropped(self):
        hardhat = [t for t in self.i["tasks"] if t["framework"] == "hardhat"]
        self.assertTrue(hardhat)
        for t in hardhat:
            self.assertFalse(t["gradable_by_the_published_grader"])
        self.assertIn("NOT implemented", self.i["grader_runner_coverage"]["hardhat"])

    def test_the_interface_is_byte_reproducible(self):
        js = json.dumps(self.i, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        self.assertEqual(js, INTERFACE.read_text(encoding="utf-8"))


class LiveForgeRunPath(unittest.TestCase):
    """`run_forge` is the only grader path that touches a toolchain, so the
    stage-ladder tests never executed it. It used to end in
    `time.time() - t0` where `t0` was local to a nested helper — a NameError on
    every real grading run, invisible to every offline test. These stub
    subprocess so that return path actually runs."""

    class _P:
        def __init__(self, rc=0, out="", err=""):
            self.returncode, self.stdout, self.stderr = rc, out, err

    def setUp(self):
        self._real_run = G.subprocess.run
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def tearDown(self):
        G.subprocess.run = self._real_run

    def _call(self, fake):
        G.subprocess.run = fake
        return G.run_forge(self.tmp, self.tmp / "t.sol", "test_x", timeout=5)

    def test_returns_duration_after_a_successful_build(self):
        res = self._call(lambda cmd, **kw: self._P(
            0, '[{"test_results":{}}]', ""))
        self.assertEqual(res["build_rc"], 0)
        self.assertIsInstance(res["duration_s"], float)

    def test_build_failure_path_also_reports_duration(self):
        res = self._call(lambda cmd, **kw: self._P(1, "", "compiler error"))
        self.assertEqual(res["build_rc"], 1)
        self.assertFalse(res["ran_tests"])
        self.assertIsInstance(res["duration_s"], float)

    def test_timeout_is_a_recorded_rc_not_an_exception(self):
        def fake(cmd, **kw):
            raise G.subprocess.TimeoutExpired(cmd, kw.get("timeout", 0))
        res = self._call(fake)
        self.assertEqual(res["build_rc"], 124)
        self.assertIn("timeout", res["stderr"])

    def test_missing_toolchain_is_rc_127_not_a_crash(self):
        def fake(cmd, **kw):
            raise FileNotFoundError("forge")
        res = self._call(fake)
        self.assertEqual(res["build_rc"], 127)


if __name__ == "__main__":
    unittest.main()
