#!/usr/bin/env python3
"""Tests for count invariants (scripts/check_manifests.py pure helpers).

Good fixtures must pass; intentionally-broken fixtures must fail.
Plus live-tree spot checks (read-only).
Run:  python -m unittest discover -s tests
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from check_manifests import (  # noqa: E402
    admitted,
    canon_key,
    decisions_sum_to_ledger,
    research_only_leak,
    splits_cover_exactly,
    task_record_id,
    tasks_resolve,
)

GOOD_LEDGER = [
    {"candidate_id": "s:1", "decision": "IMPORT"},
    {"candidate_id": "s:2", "decision": "IMPORT_AS_UNVERIFIED"},
    {"candidate_id": "s:3", "decision": "IMPORT_AS_NEGATIVE"},
    {"candidate_id": "s:4", "decision": "RESEARCH_ONLY"},
    {"candidate_id": "s:5", "decision": "CORROBORATION_ONLY"},
]

BAD_LEDGER = GOOD_LEDGER + [{"candidate_id": "s:6", "decision": "MAYBE"}]

GOOD_SPLIT = {"splits": {"train": ["a", "b"], "validation": ["c"],
                         "test": ["d"]}}
OVERLAP_SPLIT = {"splits": {"train": ["a", "b"], "validation": ["b", "c"],
                            "test": ["d"]}}
GAP_SPLIT = {"splits": {"train": ["a"], "validation": ["c"], "test": ["d"]}}

TASKS_MIXED = [
    {"source": {"record_id": "a"}, "task_id": "U_a"},
    {"source": {"record_id": "b"}, "task_id": "U_b"},
    {"finding_id": "c", "task_id": "V_c"},
    {"source": {"finding_id": "zzz"}, "task_id": "U_zzz"},
]


class TestDecisionArithmetic(unittest.TestCase):
    def test_good_ledger(self):
        self.assertTrue(decisions_sum_to_ledger(GOOD_LEDGER))
        self.assertEqual(len(admitted(GOOD_LEDGER)), 3)

    def test_broken_decision_fails(self):
        self.assertFalse(decisions_sum_to_ledger(BAD_LEDGER))

    def test_empty_ledger_trivially_consistent(self):
        self.assertTrue(decisions_sum_to_ledger([]))
        self.assertEqual(admitted([]), [])


class TestSplitCoverage(unittest.TestCase):
    def test_exact_cover(self):
        ok, why = splits_cover_exactly({"a", "b", "c", "d"}, GOOD_SPLIT)
        self.assertTrue(ok, why)

    def test_overlap_fails(self):
        ok, why = splits_cover_exactly({"a", "b", "c", "d"}, OVERLAP_SPLIT)
        self.assertFalse(ok)
        self.assertIn("b", why)

    def test_gap_fails(self):
        ok, why = splits_cover_exactly({"a", "b", "c", "d"}, GAP_SPLIT)
        self.assertFalse(ok)
        self.assertIn("b", why)


class TestTaskResolution(unittest.TestCase):
    def test_id_extraction_across_schemas(self):
        self.assertEqual(task_record_id(TASKS_MIXED[0]), "a")
        self.assertEqual(task_record_id(TASKS_MIXED[2]), "c")

    def test_dangling_task_detected(self):
        bad = tasks_resolve(TASKS_MIXED, {"a", "b", "c"})
        self.assertEqual(bad, ["zzz"])

    def test_research_leak_detected(self):
        leak = research_only_leak(TASKS_MIXED, {"b"})
        self.assertEqual(leak, ["b"])
        self.assertEqual(research_only_leak(TASKS_MIXED, {"qqq"}), [])


class TestCanonKey(unittest.TestCase):
    def test_builder_marks_stripped(self):
        row = {"record_type": "finding", "finding": {"id": "x"},
               "split": "train"}
        marked = dict(row, _quarantined_from_split="test")
        self.assertEqual(canon_key(row), canon_key(marked))

    def test_type_distinguishes_rows(self):
        a = {"record_type": "finding", "finding": {"id": "x"}}
        b = {"record_type": "exploit", "finding": {"id": "x"}}
        self.assertNotEqual(canon_key(a), canon_key(b))


class TestLiveTree(unittest.TestCase):
    def test_vbeta_split_covers_live_records(self):
        import json
        recs = {r["finding_id"] for r in (
            json.loads(l) for l in
            open(ROOT / "Vbeta/derived_vbeta/records.jsonl",
                 encoding="utf-8-sig") if l.strip())}
        split = json.load(open(ROOT / "Vbeta/splits_vbeta/split.json",
                               encoding="utf-8-sig"))
        ok, why = splits_cover_exactly(recs, split)
        self.assertTrue(ok, why)

    def test_v3_split_covers_live_records(self):
        import json
        recs = {r["finding_id"] for r in (
            json.loads(l) for l in
            open(ROOT / "derived_v3/records.jsonl", encoding="utf-8-sig")
            if l.strip())}
        split = json.load(open(ROOT / "splits_v3/split.json",
                               encoding="utf-8-sig"))
        ok, why = splits_cover_exactly(recs, split)
        self.assertTrue(ok, why)


if __name__ == "__main__":
    unittest.main(verbosity=2)
