"""The patch review must stay evidence-gated, complete, and honest.

``derived_v3/patch_reviews.jsonl`` records what changed between each patch
candidate's recorded audited revision and its recorded fix -- a static fact.
It may claim fix effectiveness only where the same valid scenario was
executed against both revisions with the violation shown only on the
vulnerable side (see ``experiments_v3/1inch-lop-m01/``); everywhere else
``fix_effectiveness`` stays ``not_testable``. No row carries L-levels or
experiment pointers, and no diff text is redistributed.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import vlun_v3 as V  # noqa: E402
from vlun_io import read_jsonl  # noqa: E402

REVIEWS = V.DERIVED_V3 / "patch_reviews.jsonl"
CANDIDATES = V.DERIVED_V3 / "patch_candidates.json"
REPORT = V.REPORTS_V3 / "patch_static_review.json"
STATUSES = {"static_diff_only", "diff_unavailable", "executed_fix_verified"}
FORBIDDEN_KEYS = {"added_sample", "removed_sample", "diff_text"}


def _walk_keys(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k
            yield from _walk_keys(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk_keys(v)


class TestPatchReviewsAreStatic(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = read_jsonl(REVIEWS)
        cls.cands = read_jsonl(CANDIDATES)

    def test_one_review_per_candidate(self):
        self.assertEqual(len(self.rows), len(self.cands))
        self.assertEqual({r["finding_id"] for r in self.rows},
                         {c["finding_id"] for c in self.cands})

    def test_candidates_still_not_testable(self):
        for c in self.cands:
            self.assertEqual(c.get("patch_status"), "not_testable",
                             c.get("finding_id"))

    def test_status_vocabulary(self):
        for r in self.rows:
            self.assertIn(r["patch_review_status"], STATUSES, r["finding_id"])

    def test_effectiveness_only_with_two_side_evidence(self):
        for r in self.rows:
            if r["fix_effectiveness"] == "not_testable":
                self.assertTrue(r["fix_effectiveness_reason"], r["finding_id"])
                continue
            self.assertEqual(r["fix_effectiveness"], "effective",
                             r["finding_id"])
            self.assertEqual(r["patch_review_status"],
                             "executed_fix_verified", r["finding_id"])
            pr = r["poc_reconstruction"]
            self.assertIs(pr["attempted"], True, r["finding_id"])
            self.assertEqual(pr["outcome"], "fix_verified_two_side",
                             r["finding_id"])
            ev = pr["evidence"]
            for side in ("vulnerable", "fixed"):
                self.assertTrue(ev[side]["result"], r["finding_id"])
                self.assertRegex(ev[side]["revision"], r"^[0-9a-f]{40}$")
            self.assertEqual(ev["vulnerable"]["revision"],
                             r["vulnerable_commit"])
            self.assertEqual(ev["fixed"]["revision"], r["fixed_commit"])
            self.assertEqual(
                (r.get("fix_locality") or {}).get("assessment"), "in_diff",
                r["finding_id"])

    def test_no_execution_claims(self):
        for r in self.rows:
            for key in ("verification_level", "experiment"):
                self.assertNotIn(key, r, r["finding_id"])
            self.assertIsNot(r.get("executed"), True)

    def test_no_diff_text_redistributed(self):
        for r in self.rows:
            self.assertFalse(FORBIDDEN_KEYS & set(_walk_keys(r)),
                             r["finding_id"])

    def test_rows_with_a_diff_cite_it(self):
        for r in self.rows:
            if r["patch_review_status"] == "diff_unavailable":
                continue
            cd = r["cited_diff"]
            self.assertRegex(cd["diff_sha256"], r"^[0-9a-f]{64}$")
            self.assertTrue(cd["compare_url"].startswith("https://github.com/"))
            self.assertEqual(len(cd["commit_urls"]), 2)
            self.assertGreaterEqual(cd["shared_with_candidates"], 1)
            st = r["diff_stats"]
            self.assertIsInstance(st["commits_between"], int)
            self.assertIn("foundry_toml", st["build_context_at_fixed"])
            if not st["paths_truncated"]:
                self.assertEqual(st["files_changed"], len(st["paths"]))

    def test_unavailable_rows_carry_no_diff(self):
        for r in self.rows:
            if r["patch_review_status"] != "diff_unavailable":
                continue
            self.assertIsNone(r["cited_diff"], r["finding_id"])
            self.assertIsNone(r["diff_stats"], r["finding_id"])
            self.assertTrue(r["diff_unavailable_reason"])
            self.assertTrue(r["diff_unavailable_detail"])

    def test_report_matches_rows(self):
        rep = json.loads(REPORT.read_text(encoding="utf-8"))
        tally: dict[str, int] = {}
        eff: dict[str, int] = {}
        for r in self.rows:
            tally[r["patch_review_status"]] = \
                tally.get(r["patch_review_status"], 0) + 1
            eff[r["fix_effectiveness"]] = \
                eff.get(r["fix_effectiveness"], 0) + 1
        self.assertEqual(rep["by_patch_review_status"], tally)
        self.assertEqual(rep["patch_candidates"], len(self.cands))
        self.assertEqual(rep["rows"], len(self.rows))
        self.assertEqual(rep["fix_effectiveness"], eff)
        self.assertEqual(sum(rep["fix_effectiveness"].values()), len(self.rows))
        n_effective = eff.get("effective", 0)
        self.assertEqual(
            rep["execution"]["outcomes"].get("fix_verified_two_side", 0),
            n_effective)
        self.assertEqual(rep["execution"]["poc_runs_performed"], n_effective)
        self.assertEqual(rep["execution"]["levels_claimed"], [])
        cited = sum(1 for r in self.rows if r.get("cited_diff"))
        self.assertEqual(rep["rows_with_cited_diff"], cited)
        self.assertEqual(rep["unique_diff_pairs"], len(rep["by_diff_pair"]))
        self.assertEqual(
            sum(p["candidates_citing"] for p in rep["by_diff_pair"]),
            cited)

    def test_fix_locality_consistency(self):
        from review_patch_candidates import FIX_LOCALITY
        got = {r["finding_id"]: r["fix_locality"] for r in self.rows
               if r.get("fix_locality")}
        self.assertEqual(set(got), set(FIX_LOCALITY))
        for fid, (target, assessment, evidence) in FIX_LOCALITY.items():
            fl = got[fid]
            self.assertEqual(fl["target"], target)
            self.assertEqual(fl["assessment"], assessment)
            self.assertIn(assessment, ("in_diff", "not_in_diff", "ambiguous"))
            self.assertTrue(fl["evidence"])
        rep = json.loads(REPORT.read_text(encoding="utf-8"))
        self.assertEqual(rep["fix_locality_assessed"], len(FIX_LOCALITY))

    def test_shared_pair_counts_on_rows(self):
        rep = json.loads(REPORT.read_text(encoding="utf-8"))
        want = {(p["vulnerable_commit"], p["fixed_commit"]):
                p["candidates_citing"] for p in rep["by_diff_pair"]}
        for r in self.rows:
            if r["patch_review_status"] == "diff_unavailable":
                continue
            self.assertEqual(
                r["cited_diff"]["shared_with_candidates"],
                want[(r["vulnerable_commit"], r["fixed_commit"])],
                r["finding_id"])


if __name__ == "__main__":
    unittest.main()
