#!/usr/bin/env python3
"""The JSON catalog must cover every committed JSON file, exactly once.

reports/json_catalog.json is a map, not a copy: if a .json/.jsonl file is
committed but missing from the catalog (or listed twice), the map has rotted.
Pure reads (catalog JSON + `git ls-files`); writes nothing.
Run:  python -m unittest tests.test_json_catalog
"""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))


class TestJsonCatalogComplete(unittest.TestCase):
    def test_every_tracked_json_is_catalogued_once(self):
        from build_json_catalog import VOLATILE_OUTPUTS
        catalog = json.loads(
            (ROOT / "reports" / "json_catalog.json").read_text(encoding="utf-8"))
        listed = [f["path"] for f in catalog["files"]]
        self.assertEqual(len(listed), len(set(listed)), "duplicate catalog entries")
        self.assertEqual(catalog["file_count"], len(listed))
        self.assertEqual(sorted(catalog["volatile_outputs"]),
                         sorted(VOLATILE_OUTPUTS))
        proc = subprocess.run(["git", "ls-files"], cwd=str(ROOT),
                              capture_output=True, text=True, timeout=120)
        self.assertEqual(proc.returncode, 0)
        excluded = tuple(catalog["excluded_prefixes"])
        own = ("reports/json_catalog.json", "reports/json_catalog.md")
        missing = [p for p in proc.stdout.splitlines()
                   if p.endswith((".json", ".jsonl"))
                   and p not in own
                   and p not in VOLATILE_OUTPUTS
                   and not any(p == e[:-1] or p.startswith(e) for e in excluded)
                   and p not in listed]
        self.assertEqual(missing, [], f"tracked JSON missing from catalog: {missing[:5]}")

    def test_categories_cover_all_files(self):
        catalog = json.loads(
            (ROOT / "reports" / "json_catalog.json").read_text(encoding="utf-8"))
        total = sum(catalog["by_category"].values())
        self.assertEqual(total, catalog["file_count"])
        for entry in catalog["files"]:
            self.assertIn(entry["category"], catalog["by_category"])


if __name__ == "__main__":
    unittest.main()
