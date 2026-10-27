"""remaining_mutable_in_source_layer has a producer and is not left null."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import resolve_citations as rc  # noqa: E402


class TestSourceLayerMutableMetric(unittest.TestCase):
    def test_producer_returns_an_int(self):
        n = rc.count_source_layer_mutable()
        self.assertIsInstance(n, int)
        self.assertGreater(n, 0)

    def test_committed_field_matches_producer(self):
        doc = json.loads(
            (ROOT / "reports" / "citation_resolution.json").read_text(
                encoding="utf-8"))
        recorded = doc.get("remaining_mutable_in_source_layer")
        self.assertIsNotNone(recorded)
        self.assertEqual(recorded, rc.count_source_layer_mutable())

    def test_missing_layer_returns_none_not_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            absent = Path(tmp) / "jsonl_not_here"
            self.assertFalse(absent.exists())
            self.assertIsNone(rc.count_source_layer_mutable(absent))

    def test_empty_layer_directory_returns_none_not_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            empty = Path(tmp)
            self.assertIsNone(rc.count_source_layer_mutable(empty))


if __name__ == "__main__":
    unittest.main()
