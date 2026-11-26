#!/usr/bin/env python3
"""README statistics invariants: every fraction is a subset, every bucket sum
names its own population.

Two defects reached a generated README while every gate stayed green:

  * `123 of 61 records state no attacker standing` -- the numerator came from
    the 137-candidate ledger, the denominator from the 61 admitted rows;
  * a manifest whose `attacker_identity`/`experiment_levels`/`quality` buckets
    still summed to 137 while `records` said 61.

`scripts/generate_readme.validate_generated_stats` is the hard guard. These
tests check it rejects both classes, that the published manifest obeys the
invariant, and that the rendered prose (families, wave1) matches it.
"""
from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import generate_readme as gr  # noqa: E402

MANIFEST = ROOT / "derived_v2_2" / "manifest.json"
README = ROOT / "README.md"


def jl(p: Path) -> list[dict]:
    with p.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


class GuardTestBase(unittest.TestCase):
    """A minimal well-formed manifest: every bucket sums to `records`."""

    def setUp(self):
        one = {"a": 1}
        self.manifest = {
            "records": 1,
            "attacker_identity": dict(one),
            "by_language": dict(one),
            "by_status": dict(one),
            "by_record_class": dict(one),
            "evidence_strongest": dict(one),
            "experiment_levels": dict(one),
            "quality": {d: dict(one) for d in ("provenance", "verification")},
        }


class TestRenderedFractionGuard(GuardTestBase):
    def test_rejects_numerator_larger_than_denominator(self):
        with self.assertRaisesRegex(AssertionError, r"123 > 61"):
            gr.validate_generated_stats("123 of 61 records state no standing",
                                        self.manifest)

    def test_accepts_a_valid_fraction(self):
        gr.validate_generated_stats("51 of 61 records state no standing",
                                    self.manifest)

    def test_accepts_a_multiline_fraction(self):
        gr.validate_generated_stats("covers 1,051 of\n7,914 tasks", self.manifest)

    def test_decimal_zero_is_not_an_integer_fraction(self):
        # `0.0000 of 1,051` is an accuracy rendered over scorable tasks, not a
        # `X of Y` subset; the guard must not read its fractional part as 0000.
        gr.validate_generated_stats("an n/a renders as 0.0000 of 1,051 tasks",
                                    self.manifest)


class TestV22ManifestBucketGuard(GuardTestBase):
    def test_rejects_a_distribution_that_sums_above_records(self):
        m = json.loads(json.dumps(self.manifest))
        m["attacker_identity"] = {"unknown": 3}
        with self.assertRaisesRegex(AssertionError,
                                    r"attacker_identity sums to 3, expected 1"):
            gr.validate_generated_stats("", m)

    def test_rejects_a_quality_bucket_that_does_not_sum_to_records(self):
        m = json.loads(json.dumps(self.manifest))
        m["quality"]["verification"] = {"reported_claim": 3}
        with self.assertRaisesRegex(AssertionError,
                                    r"quality\.verification sums to 3"):
            gr.validate_generated_stats("", m)

    def test_rejects_non_integer_buckets(self):
        m = json.loads(json.dumps(self.manifest))
        m["by_language"] = {"solidity": 0.5, "rust": 0.5}
        with self.assertRaisesRegex(AssertionError,
                                    r"by_language has non-integer buckets"):
            gr.validate_generated_stats("", m)

    def test_rejects_candidate_distribution_with_wrong_denominator(self):
        m = json.loads(json.dumps(self.manifest))
        m["candidate_count"] = 4
        m["experiment_levels_over_candidates"] = {"L4": 3}
        with self.assertRaisesRegex(
                AssertionError,
                r"experiment_levels_over_candidates sums to 3, expected 4"):
            gr.validate_generated_stats("", m)


class TestPublishedV22ManifestIsAdmitted(GuardTestBase):
    @classmethod
    def setUpClass(cls):
        cls.m = json.loads(MANIFEST.read_text(encoding="utf-8"))
        cls.rows = jl(ROOT / "derived_v2_2" / "records.jsonl")

    def test_every_admitted_distribution_sums_to_records(self):
        self.assertEqual(self.m["records"], len(self.rows))
        for key in gr.D22_DISTRIBUTIONS:
            with self.subTest(key=key):
                self.assertIsInstance(self.m[key], dict)
                self.assertEqual(sum(self.m[key].values()), self.m["records"])
        for dim, buckets in self.m["quality"].items():
            with self.subTest(dim=dim):
                self.assertEqual(sum(buckets.values()), self.m["records"])

    def test_every_candidate_distribution_sums_to_candidate_count(self):
        self.assertEqual(self.m["candidate_count"], 137)
        self.assertEqual(self.m["candidate_count"],
                         self.m["records"] + self.m["quarantined_count"])
        for key in gr.D22_DISTRIBUTIONS:
            with self.subTest(key=key):
                self.assertEqual(sum(self.m[key + "_over_candidates"].values()),
                                 self.m["candidate_count"])
        for dim, buckets in self.m["quality_over_candidates"].items():
            with self.subTest(dim=dim):
                self.assertEqual(sum(buckets.values()),
                                 self.m["candidate_count"])

    def test_buckets_are_recomputed_from_the_admitted_rows(self):
        import collections
        attacks = collections.Counter(
            (r.get("attacker_model") or {}).get("identity") for r in self.rows)
        levels = collections.Counter(
            (r.get("experiment_view") or {}).get("level") or "none"
            for r in self.rows)
        self.assertEqual(self.m["attacker_identity"], dict(attacks))
        self.assertEqual(self.m["experiment_levels"], dict(levels))
        # The old defect: the candidate bucket printed as a fraction of 61.
        self.assertEqual(self.m["attacker_identity"]["unknown"], 51)
        self.assertEqual(self.m["attacker_identity_over_candidates"]["unknown"],
                         123)

    def test_count_domains_name_both_populations(self):
        domains = self.m["count_domains"]
        for key in (*gr.D22_DISTRIBUTIONS, "records", "quality"):
            self.assertIn("admitted", domains[key], key)
        for key in gr.D22_DISTRIBUTIONS:
            self.assertIn("candidate", domains[key + "_over_candidates"], key)


class TestRenderedProseIsConsistent(GuardTestBase):
    @classmethod
    def setUpClass(cls):
        cls.readme = README.read_text(encoding="utf-8")

    def test_generated_document_passes_the_guard(self):
        gr.validate_generated_stats(gr.render() + gr.render_v4())

    def test_committed_readme_has_no_x_greater_than_y(self):
        for m in gr.X_OF_Y_RE.finditer(self.readme):
            x = int(m.group(1).replace(",", ""))
            y = int(m.group(2).replace(",", ""))
            self.assertLessEqual(x, y, f"README renders {m.group(0).strip()!r}")

    def test_attacker_fraction_uses_admitted_numerator(self):
        self.assertIn("51 of 61 records state no attacker standing", self.readme)
        self.assertNotIn("123 of 61 records", self.readme)

    def test_family_count_matches_the_families_named(self):
        # Same population rule as the generator: one family per leading letter
        # across the three benchmark manifests (Fa/Fb are F's sub-tasks).
        def tasks(rel):
            return json.loads((ROOT / rel).read_text(encoding="utf-8")).get(
                "tasks") or {}

        letters = set()
        for rel in ("benchmark/manifest.json", "benchmark/v3_manifest.json",
                    "Vbeta/benchmark_vbeta/vbeta_manifest.json"):
            for key in tasks(rel):
                base = key[:-6] if key.endswith(".jsonl") else key
                if base.startswith(("v3_", "vbeta_")):
                    base = base.split("_")[1]
                letters.add(base[0])
        ordered = sorted(letters)
        self.assertEqual(len(ordered), 22)
        self.assertIn(f"{len(ordered)} families A-{ordered[-1]}", self.readme)
        self.assertNotIn("19 families", self.readme)

    def test_wave1_row_no_longer_carries_the_stale_tag(self):
        row = re.search(r"^\| wave1 \| ([^|]+) \|", self.readme, re.M)
        self.assertIsNotNone(row)
        self.assertEqual(row.group(1).strip(), "research tree")
        self.assertNotIn("isolated METADATA_ONLY research tree", self.readme)
        self.assertIn("## wave1 layer (research tree)", self.readme)


if __name__ == "__main__":
    unittest.main(verbosity=2)
