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

#: The catalog's own two outputs, and the gate outputs whose bytes vary by
#: design. Neither is catalogued, so neither may be demanded of the catalog.
SELF_OUTPUTS = ("reports/json_catalog.json", "reports/json_catalog.md")


def tracked_paths() -> list[str]:
    """Every path the git index tracks."""
    proc = subprocess.run(["git", "ls-files"], cwd=str(ROOT),
                          capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        raise AssertionError(f"git ls-files failed: {proc.stderr[:400]}")
    return proc.stdout.splitlines()


def missing_from_catalog(catalog: dict, tracked: list[str]) -> list[str]:
    """The tracked JSON files that exist in the working tree and are not
    catalogued.

    A tracked path whose file is GONE from the working tree is not missing
    from the catalog: the catalog is a map of the working tree (that is what
    `scripts/build_json_catalog.py` scans), and a file that was deleted has
    no bytes to describe.  Such a path is still tracked in the index until
    the deletion is committed, so the index alone is not the tree.  This
    helper therefore requires the file to EXIST before demanding it of the
    catalog -- and the companion test below proves that a file which does
    exist and is tracked is still caught when the catalog omits it.
    """
    from build_json_catalog import VOLATILE_OUTPUTS
    listed = [f["path"] for f in catalog["files"]]
    excluded = tuple(catalog["excluded_prefixes"])
    out = []
    for p in tracked:
        if not p.endswith((".json", ".jsonl")):
            continue
        if p in SELF_OUTPUTS:
            continue
        if p in VOLATILE_OUTPUTS:
            continue
        if any(p == e[:-1] or p.startswith(e) for e in excluded):
            continue
        if p in listed:
            continue
        if not (ROOT / p).is_file():
            # tracked in the index, deleted from the working tree: nothing
            # left to catalogue.
            continue
        out.append(p)
    return out


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
        missing = missing_from_catalog(catalog, tracked_paths())
        self.assertEqual(missing, [], f"tracked JSON missing from catalog: {missing[:5]}")

    def test_a_tracked_file_missing_from_the_catalog_is_still_caught(self):
        """The rule must still bite.

        The working-tree rule above can only be satisfied by a catalog that
        omits nothing that exists.  This test takes a real, existing, tracked
        JSON file, drops it from the catalog in memory, and requires the
        detector to report it: a rule that silently passes whenever the
        catalog is incomplete would be worthless.
        """
        catalog = json.loads(
            (ROOT / "reports" / "json_catalog.json").read_text(encoding="utf-8"))
        tracked = tracked_paths()
        present = [p for p in tracked
                   if p.endswith((".json", ".jsonl"))
                   and p not in SELF_OUTPUTS
                   and (ROOT / p).is_file()
                   and any(f["path"] == p for f in catalog["files"])]
        self.assertTrue(present, "no tracked, existing, catalogued JSON file "
                                 "to use as the control")
        victim = sorted(present)[0]
        self.assertNotIn(victim, missing_from_catalog(catalog, tracked),
                         "the catalog is expected to list this file")
        broken = dict(catalog)
        broken["files"] = [f for f in catalog["files"] if f["path"] != victim]
        self.assertIn(victim, missing_from_catalog(broken, tracked),
                      "a tracked file that exists and is absent from the "
                      "catalog must still be reported")

    def test_categories_cover_all_files(self):
        catalog = json.loads(
            (ROOT / "reports" / "json_catalog.json").read_text(encoding="utf-8"))
        total = sum(catalog["by_category"].values())
        self.assertEqual(total, catalog["file_count"])
        for entry in catalog["files"]:
            self.assertIn(entry["category"], catalog["by_category"])


if __name__ == "__main__":
    unittest.main()
