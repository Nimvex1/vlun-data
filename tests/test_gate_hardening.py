"""Regression tests for the gate-hardening pass.

Each test pins one defect class from the review so it cannot silently
reappear: fail-closed gates, required manifest keys, explicit unknowns,
a single splits directory, and a working --only subset runner.
"""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))


class TestGateVerdict(unittest.TestCase):
    def test_all_skipped_is_failure(self):
        """A build that verifies nothing must not exit 0."""
        from run_gates import overall_rc
        self.assertEqual(overall_rc([]), 1)
        self.assertEqual(
            overall_rc([("a", "SKIPPED"), ("b", "SKIPPED")]), 1)

    def test_mixed_skip_still_passes(self):
        from run_gates import overall_rc
        self.assertEqual(
            overall_rc([("a", "PASS"), ("b", "SKIPPED")]), 0)

    def test_any_fail_fails(self):
        from run_gates import overall_rc
        self.assertEqual(
            overall_rc([("a", "PASS"), ("b", "FAIL")]), 1)

    def test_only_subset_runs(self):
        """--only used to KeyError on every subset; the proof group must run."""
        r = subprocess.run(
            [sys.executable, "scripts/run_gates.py", "--only", "proof"],
            cwd=str(ROOT), capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("proof-hashes-current", r.stdout)


class TestManifestKeysRequired(unittest.TestCase):
    def test_every_family_file_has_a_manifest_key(self):
        """The .get(key, len(tasks)) auto-pass hid a missing T key. Every
        benchmark family file must resolve to a manifest entry, so a
        renamed or dropped key fails instead of self-comparing."""
        v3m = json.loads(
            (ROOT / "benchmark" / "v3_manifest.json").read_text(
                encoding="utf-8"))["tasks"]
        for fname, mkey in [
                ("v3_R_source_tier_routing.jsonl", "R_v3_source_tier_routing"),
                ("retired_families/v3_S_contest_outcome.jsonl", "S_v3_contest_outcome"),
                ("retired_families/v3_T_taxonomy_explicit.jsonl", "T_v31_taxonomy_explicit")]:
            rows = sum(1 for _ in (ROOT / "benchmark" / fname).open(
                encoding="utf-8"))
            self.assertIn(mkey, v3m, f"manifest key {mkey!r} missing")
            self.assertEqual(v3m[mkey], rows)
        vb = json.loads(
            (ROOT / "Vbeta" / "benchmark_vbeta" / "vbeta_manifest.json")
            .read_text(encoding="utf-8"))["tasks"]
        for fam, fname in (("U", "vbeta_U_language_routing.jsonl"),
                           ("V", "vbeta_V_source_tier_routing.jsonl")):
            vkey = (f"vbeta_{fam}_"
                    f"{'language_routing' if fam == 'U' else 'source_tier_routing'}")
            rows = sum(1 for _ in (
                ROOT / "Vbeta" / "benchmark_vbeta" / fname).open(
                encoding="utf-8"))
            self.assertIn(vkey, vb, f"manifest key {vkey!r} missing")
            self.assertEqual(vb[vkey], rows)


class TestExplicitUnknowns(unittest.TestCase):
    def test_ingest_reports_metric_errors_key(self):
        """Failed metric imports must be unknown-with-reason, never zero."""
        import ingest_audit_sources as I
        f, s, d = I.load_layer()
        m = I.compute_metrics([], f, s, d)
        self.assertIn("metric_errors", m)
        self.assertIsInstance(m["metric_errors"], list)
        self.assertEqual(I._show(None), "unknown (see metric_errors)")
        self.assertEqual(I._show(8), "8")

    def test_field_coverage_missing_layer_is_explicit(self):
        """A missing layer file must fail --check loudly, not vanish."""
        import shutil
        target = ROOT / "derived" / "records.jsonl"
        backup = ROOT / "derived_records.jsonl.bak"
        self.assertTrue(target.is_file())
        shutil.move(str(target), str(backup))
        try:
            r = subprocess.run(
                [sys.executable, "scripts/field_coverage.py", "--check"],
                cwd=str(ROOT), capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0)
        finally:
            shutil.move(str(backup), str(target))
        r = subprocess.run(
            [sys.executable, "scripts/field_coverage.py", "--check"],
            cwd=str(ROOT), capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


class TestSingleSplitsSource(unittest.TestCase):
    def test_shipped_splits_are_splits_v2(self):
        """splits/ (pre-quarantine) was retired: one counter, one truth."""
        import vlun
        self.assertEqual(vlun.SPLITS_DIR, ROOT / "splits_v2")
        self.assertFalse((ROOT / "splits").exists(),
                         "retired splits/ directory reappeared")
        splits = vlun.load_splits()
        self.assertEqual(sorted(splits), ["test", "train", "validation"])
        self.assertEqual(len(splits["train"]), 413)


if __name__ == "__main__":
    unittest.main()