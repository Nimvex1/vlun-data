"""Benchmark B/G: the scalar projections must be derived from structure only.

Both families were previously 0-scorable. B now scores
`invariant_stated` and G scores the L6-verified subset. These tests pin the
property that makes those projections defensible: the label is read from
record structure, never from the prose it sits next to, so a model cannot
game it and a judge-free score means something.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))


def _rows(p):
    return [json.loads(line) for line in p.open(encoding="utf-8") if line.strip()]


class TestFamilyB(unittest.TestCase):
    def setUp(self):
        self.rows = _rows(ROOT / "benchmark" / "retired_families" / "B_root_cause_reasoning.jsonl")

    def test_has_scorable_rows(self):
        labeled = [r for r in self.rows if r["answer_key_status"] == "labeled"]
        self.assertGreater(len(labeled), 0,
                           "B must admit scorable rows, not be decorative")

    def test_scalar_matches_invariant_presence(self):
        for r in self.rows:
            ak = r["answer_key"]
            has_inv = bool(ak.get("violated_invariant"))
            want = "invariant_stated" if has_inv else "no_invariant_stated"
            self.assertEqual(ak.get("invariant_stated"), want, r["id"])

    def test_labeled_iff_invariant_present(self):
        for r in self.rows:
            has_inv = bool(r["answer_key"].get("violated_invariant"))
            self.assertEqual(r["answer_key_status"] == "labeled", has_inv, r["id"])

    def test_no_invariant_rows_are_excluded_with_reason(self):
        for r in self.rows:
            if r["answer_key_status"] == "labeled":
                continue
            self.assertTrue(r.get("unlabelled_reason"),
                            f"{r['id']}: excluded without a reason")

    def test_scalar_is_not_leaked_in_input(self):
        # The answer must not appear in the model-facing input.
        for r in self.rows:
            blob = json.dumps(r.get("input"), sort_keys=True).lower()
            self.assertNotIn("invariant_stated", blob, r["id"])
            self.assertNotIn("no_invariant_stated", blob, r["id"])


class TestFamilyG(unittest.TestCase):
    def setUp(self):
        self.rows = _rows(ROOT / "benchmark" / "G_patch_verification.jsonl")

    def test_has_scorable_rows(self):
        labeled = [r for r in self.rows if r["answer_key_status"] == "labeled"]
        self.assertGreater(len(labeled), 0,
                           "G must admit its L6-verified subset")

    def test_labeled_rows_have_both_execution_legs(self):
        for r in self.rows:
            if r["answer_key_status"] != "labeled":
                continue
            refs = [x for x in (r.get("execution_refs") or []) if x]
            self.assertEqual(len(refs), 2, f"{r['id']}: needs both legs")
            for ref in refs:
                self.assertTrue((ROOT / ref).is_dir(),
                                f"{r['id']}: missing {ref}")

    def test_unlabeled_rows_have_no_answer(self):
        for r in self.rows:
            if r["answer_key_status"] == "labeled":
                continue
            self.assertIsNone(r["answer_key"].get("label"), r["id"])
            self.assertTrue(r.get("unlabelled_reason"), r["id"])

    def test_labeled_subset_is_l6_only(self):
        pv = json.loads((ROOT / "reports" / "patch_verification_v2.json")
                        .read_text(encoding="utf-8"))
        effective = {r["finding_id"] for r in pv["records"]
                     if r.get("fix_effectiveness") in
                     ("effective", "ineffective", "partially_effective")}
        for r in self.rows:
            fid = (r.get("source") or {}).get("finding_id")
            self.assertEqual(r["answer_key_status"] == "labeled",
                             fid in effective, r["id"])


class TestNoFamilyIsDecorative(unittest.TestCase):
    def test_every_family_has_scorable_rows(self):
        man = json.loads((ROOT / "benchmark" / "manifest.json")
                         .read_text(encoding="utf-8"))
        zero = sorted(f for f, spec in man["tasks"].items()
                      if spec.get("scorable", 0) == 0)
        self.assertEqual(zero, [], f"families with no scorable rows: {zero}")

    def test_accounting_adds_up_everywhere(self):
        man = json.loads((ROOT / "benchmark" / "manifest.json")
                         .read_text(encoding="utf-8"))
        for fam, spec in man["tasks"].items():
            self.assertEqual(spec["scorable"] + spec["unscorable"],
                             spec["tasks"], fam)


if __name__ == "__main__":
    unittest.main(verbosity=2)