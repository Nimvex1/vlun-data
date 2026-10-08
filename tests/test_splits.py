#!/usr/bin/env python3
"""Tests that the monolith splits kept a stable surface and behavior.

scripts/validate.py, scripts/build_v3.py and scripts/normalize_v3.py were
split into *_checks.py / *_harvest.py / *_lib.py modules. These tests pin:
every check/harvest/normalize callable the orchestrators import still
exists, and every script still exposes its documented --help surface.
Behavioural equivalence is proven by byte-identical gate/build outputs
(see reports/reproducibility_report.md); these tests guard the seams.
Run:  python -m unittest discover -s tests
"""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))


class TestSplitSurfaces(unittest.TestCase):
    def test_validate_checks_surface(self):
        import validate_checks as vc
        for name in ("load_core_dict", "check_structure", "check_provenance",
                     "check_consistency", "check_evidence", "check_splits",
                     "check_derived_layer", "check_online", "check_v21",
                     "check_v22", "check_v22_layer", "check_audit_sources"):
            self.assertTrue(callable(getattr(vc, name, None)), name)

    def test_build_v3_harvest_surface(self):
        import build_v3_harvest as h
        for name in ("harvest_c4", "harvest_sherlock", "harvest_pashov",
                     "harvest_smartbugs", "harvest_defihacklabs",
                     "harvest_zellic", "harvest_certora", "harvest_cyba",
                     "harvest_sigmaprime", "harvest_anza",
                     "harvest_flat_pdfs", "harvest_ackee", "harvest_abdk",
                     "harvest_informal", "_load_existing_overlap"):
            self.assertTrue(callable(getattr(h, name, None)), name)

    def test_normalize_v3_lib_surface(self):
        import normalize_v3_lib as lib
        for name in ("normalize_severity", "map_taxonomy",
                     "resolve_lang_eco", "classify_commit_context",
                     "_emit_fragment", "_coverage", "_corroborate"):
            self.assertTrue(callable(getattr(lib, name, None)), name)

    def test_help_surfaces_stable(self):
        for script, wants in [
                ("scripts/validate.py", ["--quiet", "--online"]),
                ("scripts/build_v3.py", ["--check"]),
                ("scripts/normalize_v3.py",
                 ["--check", "--limit-sources"])]:
            p = subprocess.run(
                [sys.executable, script, "--help"], cwd=str(ROOT),
                capture_output=True, text=True, timeout=60)
            self.assertEqual(p.returncode, 0, script)
            for flag in wants:
                self.assertIn(flag, p.stdout, f"{script} {flag}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
