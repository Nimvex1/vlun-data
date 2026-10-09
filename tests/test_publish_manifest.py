"""publish_manifest.json: records_written must be explainable and verified.

records_written (1898) is the historical v1 publish figure and is NOT a
distinct-record count -- it counts jsonl/ rows plus splits_v2/ pointer rows.
Nothing previously said so, so the number read as a record count it is not.
This test recomputes it and pins the breakdown, so the ambiguity cannot
silently return.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
JSONL = ("findings", "negative_findings", "exploits", "patches",
         "protocol", "metadata", "errors")
SPLITS = ("train", "validation", "test", "quarantine")


def _rows(p: Path) -> int:
    with p.open(encoding="utf-8") as fh:
        return sum(1 for line in fh if line.strip())


class TestPublishManifest(unittest.TestCase):
    def setUp(self):
        self.m = json.loads((ROOT / "publish_manifest.json")
                            .read_text(encoding="utf-8"))

    def test_records_written_breakdown_present(self):
        bd = self.m.get("records_written_breakdown")
        self.assertIsNotNone(bd,
                             "records_written needs a breakdown: it is not a "
                             "distinct-record count")
        self.assertTrue(bd.get("note"))

    def test_records_written_is_flagged(self):
        self.assertIs(self.m.get("records_written_is_not_a_record_count"), True)

    def test_breakdown_recomputes(self):
        jsonl_rows = sum(_rows(ROOT / "jsonl" / f"{n}.jsonl") for n in JSONL)
        split_rows = sum(_rows(ROOT / "splits_v2" / f"{s}.jsonl")
                         for s in SPLITS)
        bd = self.m["records_written_breakdown"]
        self.assertEqual(bd["jsonl_source_rows"], jsonl_rows)
        self.assertEqual(bd["splits_v2_rows"], split_rows)
        self.assertEqual(self.m["records_written"], jsonl_rows + split_rows)

    def test_redaction_counts_are_present(self):
        for k in ("code_context_entries_removed", "source_lines_withheld",
                  "patch_diffs_removed"):
            self.assertIsInstance(self.m.get(k), int, k)
            self.assertGreater(self.m[k], 0, k)


if __name__ == "__main__":
    unittest.main(verbosity=2)