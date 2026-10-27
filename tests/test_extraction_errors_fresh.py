"""extraction_errors.json freshness is gated, and stale findings are not
silently deleted.
"""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import generate_reports as gr  # noqa: E402


class TestExtractionErrorsFreshness(unittest.TestCase):
    def test_check_mode_matches_committed(self):
        r = subprocess.run(
            [sys.executable, "scripts/generate_reports.py", "--check"],
            cwd=str(ROOT), capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_stale_fixture_fails_check(self):
        path = ROOT / "reports" / "extraction_errors.json"
        original = path.read_text(encoding="utf-8")
        try:
            stale = json.loads(original)
            stale["total"] = -1
            path.write_text(json.dumps(stale, indent=2, sort_keys=True) + "\n",
                            encoding="utf-8", newline="\n")
            r = subprocess.run(
                [sys.executable, "scripts/generate_reports.py", "--check"],
                cwd=str(ROOT), capture_output=True, text=True, timeout=120)
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("STALE", (r.stdout or "") + (r.stderr or ""))
        finally:
            path.write_text(original, encoding="utf-8", newline="\n")

    def test_validation_failures_are_not_still_true_when_gate_is_ok(self):
        doc = json.loads(
            (ROOT / "reports" / "extraction_errors.json").read_text(
                encoding="utf-8"))
        vrep = json.loads(
            (ROOT / "reports" / "validation_report.json").read_text(
                encoding="utf-8"))
        ok_checks = {c["check"] for c in vrep.get("details") or []
                     if c.get("ok") and c.get("failure_count") == 0}
        for e in doc.get("entries") or []:
            if e.get("kind") != "validation_failure":
                continue
            check = (e.get("summary") or "").removeprefix(
                "validation gate: ").strip()
            if check in ok_checks:
                self.assertNotEqual(e.get("still_true"), True, e)
                self.assertEqual(e.get("state"), "resolved", e)
                self.assertTrue(e.get("resolution"), e)

    def test_every_finding_has_a_state(self):
        doc = json.loads(
            (ROOT / "reports" / "extraction_errors.json").read_text(
                encoding="utf-8"))
        for e in doc.get("entries") or []:
            self.assertIn(e.get("state"), gr.FINDING_STATES, e)
            self.assertTrue(e.get("finding_id"), e)
            if e.get("state") != "open":
                self.assertTrue(e.get("resolution"), e)

    def test_license_finding_not_resolved_just_because_manifest_exists(self):
        import tempfile
        from unittest import mock
        prev = {
            "origin": "v2",
            "kind": "license_not_declared",
            "repository": "acme/unlicensed",
            "summary": "acme/unlicensed has no LICENSE file at any cited commit",
        }
        with tempfile.TemporaryDirectory() as tmp:
            man = Path(tmp) / "source_manifest.json"
            man.write_text(json.dumps({
                "repos": [{"repo": "other/x", "license": {"found": True}}],
            }), encoding="utf-8")
            with mock.patch.object(gr, "WORK", Path(tmp)):
                row = gr.adjudicate_absent(prev, gr.finding_id(prev))
        self.assertEqual(row["state"], "unverifiable", row)
        self.assertNotEqual(row.get("still_true"), False)

    def test_license_resolved_only_with_that_repo_license(self):
        import tempfile
        from unittest import mock
        prev = {
            "origin": "v2",
            "kind": "license_not_declared",
            "repository": "acme/now-licensed",
            "summary": "acme/now-licensed has no LICENSE file at any cited commit",
        }
        with tempfile.TemporaryDirectory() as tmp:
            man = Path(tmp) / "source_manifest.json"
            man.write_text(json.dumps({
                "repos": [{"repo": "acme/now-licensed",
                           "license": {"found": True, "spdx": "MIT"}}],
            }), encoding="utf-8")
            with mock.patch.object(gr, "WORK", Path(tmp)):
                row = gr.adjudicate_absent(prev, gr.finding_id(prev))
        self.assertEqual(row["state"], "resolved", row)
        self.assertFalse(row["still_true"])
        self.assertEqual(row["resolution"]["repository"], "acme/now-licensed")

    def test_historical_entries_are_not_dropped(self):
        doc = json.loads(
            (ROOT / "reports" / "extraction_errors.json").read_text(
                encoding="utf-8"))
        self.assertGreaterEqual(doc["total"], 19)
        origins = {e.get("origin") for e in doc["entries"]}
        self.assertIn("v1", origins)


if __name__ == "__main__":
    unittest.main()
