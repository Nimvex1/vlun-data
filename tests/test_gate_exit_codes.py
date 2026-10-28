"""Skip must never be recorded as PASS.

Covers the path from a --check script's exit code through run_gates.py
status classification, including unexpected exits, launch errors and
timeouts. Missing-input tests use a controlled path, not the real
git-ignored work/prove_candidates tree.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import run_gates as rg  # noqa: E402


class TestClassifyStatus(unittest.TestCase):
    def test_zero_is_pass(self):
        self.assertEqual(rg.classify_status(0), "PASS")

    def test_two_is_skipped(self):
        self.assertEqual(rg.classify_status(2), "SKIPPED")

    def test_one_is_fail(self):
        self.assertEqual(rg.classify_status(1), "FAIL")

    def test_unexpected_code_is_fail(self):
        self.assertEqual(rg.classify_status(99), "FAIL")
        self.assertEqual(rg.classify_status(None), "FAIL")

    def test_timeout_is_fail_not_skip(self):
        self.assertEqual(rg.classify_status(None, error="timeout after 1200s"),
                         "FAIL")

    def test_launch_error_is_fail_not_skip(self):
        self.assertEqual(rg.classify_status(None, error="cannot start: boom"),
                         "FAIL")

    def test_error_wins_over_zero(self):
        self.assertEqual(rg.classify_status(0, error="cannot start: x"), "FAIL")


class TestProveLedgerSkipCode(unittest.TestCase):
    def _absent_env(self) -> dict[str, str]:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        env = os.environ.copy()
        env["VLUN_PROVE_CANDIDATES"] = str(
            Path(tmp.name) / "prove_candidates_absent")
        return env

    def test_missing_local_inputs_exit_two(self):
        env = self._absent_env()
        self.assertFalse(Path(env["VLUN_PROVE_CANDIDATES"]).exists())
        r = subprocess.run(
            [sys.executable, "scripts/build_prove_ledger.py", "--check"],
            cwd=str(ROOT), capture_output=True, text=True, timeout=60,
            env=env)
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        combined = (r.stdout or "") + (r.stderr or "")
        self.assertIn("skipped_no_network", combined)

    def test_empty_candidate_dir_is_still_a_skip(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["VLUN_PROVE_CANDIDATES"] = tmp
            r = subprocess.run(
                [sys.executable, "scripts/build_prove_ledger.py", "--check"],
                cwd=str(ROOT), capture_output=True, text=True, timeout=60,
                env=env)
            self.assertEqual(r.returncode, 2, r.stdout + r.stderr)

    def test_run_gates_records_skip_not_pass(self):
        env = self._absent_env()
        r = subprocess.run(
            [sys.executable, "scripts/run_gates.py", "--only", "prove"],
            cwd=str(ROOT), capture_output=True, text=True, timeout=180,
            env=env)
        out = r.stdout + r.stderr
        self.assertIn("prove-ledger-current", out)
        self.assertRegex(out, r"\[SKIPPED\] prove-ledger-current")
        self.assertNotRegex(out, r"\[PASS\] prove-ledger-current")


if __name__ == "__main__":
    unittest.main()
