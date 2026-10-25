"""The IAA sample is frozen: templates came from it, so drift must fail the gate.

A redraw is allowed only into a separately versioned directory; overwriting the v1
sample would silently redefine a distributed worksheet and invalidate any annotations
collected against it.
"""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import sample_iaa  # noqa: E402


class TestFrozenSample(unittest.TestCase):
    def test_frozen_artifacts_match_manifest(self):
        self.assertEqual(sample_iaa.frozen_errors(ROOT), [])

    def test_check_mode_passes(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "sample_iaa.py"), "--check"],
            cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_sample_and_templates_carry_the_same_rows(self):
        rows = [json.loads(line) for line in
                (ROOT / "annotation" / "iaa_v1" / "sample.jsonl")
                .read_text(encoding="utf-8").splitlines()[1:] if line.strip()]
        sample_ids = {r["sample_id"] for r in rows}
        self.assertEqual(len(sample_ids), 300)
        for name in sample_iaa.TEMPLATES:
            import csv
            with (ROOT / "annotation" / "iaa_v1" / "blank" / name).open(
                    newline="", encoding="utf-8") as fh:
                template_ids = {r["sample_id"] for r in csv.DictReader(fh)}
            self.assertEqual(template_ids, sample_ids, name)

    def test_drift_is_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "annotation" / "iaa_v1"
            (base / "blank").mkdir(parents=True)
            shutil.copy(ROOT / "annotation" / "iaa_v1" / "sample.jsonl", base)
            for name in sample_iaa.TEMPLATES:
                shutil.copy(ROOT / "annotation" / "iaa_v1" / "blank" / name,
                            base / "blank" / name)
            manifest = json.loads((ROOT / "annotation" / "iaa_v1" / "frozen_sample.json")
                                  .read_text(encoding="utf-8"))
            manifest["sample_sha256"] = "0" * 64
            (base / "frozen_sample.json").write_text(json.dumps(manifest), encoding="utf-8")
            errors = sample_iaa.frozen_errors(tmp)
            self.assertTrue(any("sample.jsonl" in error for error in errors), errors)

    def test_redraw_refuses_the_v1_directory(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "sample_iaa.py"), "--redraw",
             "--out", "annotation/iaa_v1", "--draw-version", "iaa-draw-2.0",
             "--seed", "1", "--rationale", "test"],
            cwd=ROOT, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must not be annotation/iaa_v1", result.stderr)

    def test_redraw_requires_a_new_version_and_explicit_seed(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "sample_iaa.py"), "--redraw",
             "--out", "annotation/iaa_v2", "--draw-version", "iaa-draw-1.0",
             "--seed", "1", "--rationale", "test"],
            cwd=ROOT, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("frozen v1 draw", result.stderr)


if __name__ == "__main__":
    unittest.main()
