"""check_leakage.py --emit must not silently erase curated quarantine."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_leakage as cl  # noqa: E402


def _row(fid: str) -> dict:
    return {"finding": {"id": fid}, "source": {"repository": "r/" + fid}}


class TestCuratedOverwriteDecision(unittest.TestCase):
    def test_empty_proposed_against_populated_is_blocked(self):
        d = cl.curated_overwrite_decision(
            [_row("a"), _row("b")], [], allow_rewrite=False)
        self.assertTrue(d["blocked"])
        self.assertTrue(d["emptying"])
        self.assertEqual(d["existing_n"], 2)
        self.assertEqual(d["proposed_n"], 0)

    def test_override_allows_emptying(self):
        d = cl.curated_overwrite_decision(
            [_row("a")], [], allow_rewrite=True)
        self.assertFalse(d["blocked"])
        self.assertTrue(d["emptying"])
        self.assertEqual(d["removed"], [cl.rec_id(_row("a"))])

    def test_noop_is_allowed(self):
        rows = [_row("a"), _row("b")]
        d = cl.curated_overwrite_decision(rows, rows, allow_rewrite=False)
        self.assertFalse(d["blocked"])
        self.assertEqual(d["removed"], [])
        self.assertEqual(d["added"], [])
        self.assertEqual(d["existing_sha256"], d["proposed_sha256"])

    def test_addition_without_removal_is_allowed(self):
        d = cl.curated_overwrite_decision(
            [_row("a")], [_row("a"), _row("b")], allow_rewrite=False)
        self.assertFalse(d["blocked"])
        self.assertEqual(len(d["added"]), 1)

    def test_removal_without_override_is_blocked(self):
        d = cl.curated_overwrite_decision(
            [_row("a"), _row("b")], [_row("a")], allow_rewrite=False)
        self.assertTrue(d["blocked"])
        self.assertTrue(d["shrinking"])
        self.assertEqual(len(d["removed"]), 1)

    def test_hashes_differ_when_content_differs(self):
        d = cl.curated_overwrite_decision(
            [_row("a")], [_row("b")], allow_rewrite=True)
        self.assertNotEqual(d["existing_sha256"], d["proposed_sha256"])


class TestCommittedQuarantineUntouchedByDecision(unittest.TestCase):
    def test_live_quarantine_has_two_rows(self):
        path = ROOT / "splits_v2" / "quarantine.jsonl"
        n = sum(1 for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip())
        self.assertEqual(n, 2)


if __name__ == "__main__":
    unittest.main()
