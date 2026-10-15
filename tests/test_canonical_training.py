#!/usr/bin/env python3
"""Canonical training views stay flat, labeled, split and budgeted.

Run:  python -m unittest tests.test_canonical_training
"""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CANON = ROOT / "training" / "canonical"

REQUIRED = {"example_id", "task", "split", "layer", "canonical_id",
            "supervision", "input_text", "code_ref", "label",
            "verification_level", "weight", "provenance"}
SEV = {"critical", "high", "medium", "low", "informational"}


def load(p):
    return [json.loads(x) for x in
            p.read_text(encoding="utf-8").splitlines() if x.strip()]


class TestCanonicalTraining(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(
            (CANON / "manifest.json").read_text(encoding="utf-8"))
        cls.rows = []
        for f in cls.manifest["files"]:
            cls.rows.extend(load(ROOT / f["path"]))

    def test_manifest_matches_files(self):
        self.assertEqual(self.manifest["example_count"], len(self.rows))
        total = 0
        for f in self.manifest["files"]:
            rows = load(ROOT / f["path"])
            self.assertEqual(len(rows), f["rows"], f["path"])
            self.assertLessEqual(len(rows), self.manifest["chunk_rows"])
            h = hashlib.sha256(
                (ROOT / f["path"]).read_bytes()).hexdigest()
            self.assertEqual(h, f["sha256"], f["path"])
            total += len(rows)
        self.assertEqual(total, len(self.rows))

    def test_required_keys_and_closed_vocab(self):
        for r in self.rows:
            self.assertTrue(REQUIRED.issubset(r.keys()), r.get("example_id"))
            self.assertIn(r["task"], ("severity", "language", "detection"))
            self.assertIn(r["split"], ("train", "validation", "test"))
            self.assertIn(r["supervision"], ("observed", "verified"))
            self.assertGreater(r["weight"], 0)
            self.assertLessEqual(len(r["input_text"]),
                                 self.manifest["input_budget_chars"],
                                 r["example_id"])
            if r["task"] == "severity":
                self.assertIn(r["label"], SEV, r["example_id"])
            if r["task"] == "detection":
                self.assertIsInstance(r["label"], bool)
                self.assertEqual(r["supervision"], "verified",
                                 r["example_id"])

    def test_detection_never_from_unverified_harvest(self):
        for r in self.rows:
            if r["task"] != "detection" or r["label"] is not True:
                continue
            self.assertIn(r["layer"], ("v1", "v2.2"), r["example_id"])

    def test_example_ids_unique(self):
        ids = [r["example_id"] for r in self.rows]
        self.assertEqual(len(ids), len(set(ids)))


if __name__ == "__main__":
    unittest.main()
