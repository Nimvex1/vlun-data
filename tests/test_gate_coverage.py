"""Every pipeline script is classified; critical publishers are gated or excepted."""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import gate_coverage as gc  # noqa: E402
import run_gates as rg  # noqa: E402


class TestGateCoverageInventory(unittest.TestCase):
    def test_every_script_is_classified(self):
        for rel in gc.list_scripts():
            cat = gc.classify(rel)
            self.assertIn(cat, gc.CATEGORIES, rel)

    def test_no_production_script_is_silently_ungated(self):
        doc = gc.build()
        self.assertEqual(doc["missing_ungated_reason"], [])

    def test_check_mode_matches_committed(self):
        r = subprocess.run(
            [sys.executable, "scripts/gate_coverage.py", "--check"],
            cwd=str(ROOT), capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_new_gates_are_in_only_map(self):
        named = {n for n, _ in rg.GATES}
        grouped = set()
        for names in rg.ONLY_MAP.values():
            grouped.update(names)
        missing = named - grouped
        self.assertFalse(missing, f"gates not in ANY ONLY_MAP group: {missing}")

    def test_critical_publishers_are_gated(self):
        gated = gc.gated_scripts()
        for rel in ("scripts/generate_reports.py",
                    "scripts/build_prove_ledger.py",
                    "scripts/generate_readme.py",
                    "scripts/gate_coverage.py"):
            self.assertTrue(gated.get(rel), rel)

    def test_committed_inventory_counts_match_scan(self):
        doc = json.loads(
            (ROOT / "reports" / "gate_coverage.json").read_text(
                encoding="utf-8"))
        self.assertEqual(doc["script_count"], len(gc.list_scripts()))


if __name__ == "__main__":
    unittest.main()
