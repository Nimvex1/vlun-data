#!/usr/bin/env python3
"""Fixed point for scripts/inventory_rights.py (DIGEST RULE: inputs only).

The generator used to digest its own outputs and reports/json_catalog.json
(which embeds their digests), so run N recorded run N-1's hash and rewrote;
the committed inventory could not be reproduced from a fresh clone.  These
tests pin the rule: two settled runs over the same inputs are byte-identical,
and an output file changed in place cannot move the next run.

Run:  python -m unittest tests.test_rights_fixed_point
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "inventory_rights.py"
OUTPUTS = ("reports/rights_inventory.json", "reports/rights_inventory.md",
           "reports/history_exposure.md",
           "reports/rights_history_exposure.json",
           "distribution_v1/MANIFEST.json", "distribution_v1/README.md")


def run(root: Path) -> None:
    subprocess.run([sys.executable, str(SCRIPT), "--root", str(root),
                    "--quiet"], check=True)


def snapshot(root: Path) -> dict:
    return {rel: (root / rel).read_bytes() for rel in OUTPUTS}


class RightsInventoryFixedPoint(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="vlun-rights-fp-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        (self.root / "derived").mkdir()
        (self.root / "derived" / "records.jsonl").write_text(
            json.dumps({"id": "r1", "code_context": [
                {"snippet": "contract A { function f() external {} }"}]}) + "\n",
            encoding="utf-8", newline="\n")
        # A cold tree gains output rows only when a run writes them, and the
        # rows record the previous outputs' sizes; a checkout already holds
        # both.  Settle first, exactly as a checkout with stale outputs does.
        previous = None
        for _ in range(6):
            run(self.root)
            current = snapshot(self.root)
            if current == previous:
                break
            previous = current
        else:
            self.fail("inventory_rights.py did not converge on a cold tree")

    def test_two_runs_are_byte_identical(self) -> None:
        run(self.root)
        first = snapshot(self.root)
        run(self.root)
        self.assertEqual(snapshot(self.root), first)

    def test_changing_an_output_in_place_cannot_move_the_next_run(self) -> None:
        baseline = snapshot(self.root)
        for rel in ("reports/rights_inventory.json",
                    "distribution_v1/MANIFEST.json"):
            p = self.root / rel
            text = p.read_text(encoding="utf-8")
            # same-length change: a recorded digest becomes zeros, so only
            # the output file changes, never an input's bytes or size
            digest = re.search(r"[0-9a-f]{64}", text).group(0)
            p.write_text(text.replace(digest, "0" * 64, 1),
                         encoding="utf-8", newline="\n")
        run(self.root)
        self.assertEqual(snapshot(self.root), baseline)
