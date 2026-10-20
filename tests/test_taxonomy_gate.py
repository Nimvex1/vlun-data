"""Gate tests for item 16 (root-cause taxonomy) and item 14's honesty guards.

Each broken fixture under tests/fixtures/broken/ must make the relevant script fail with
a reason that names the defect. The two IAA fixtures are the ones that matter most: a
report that claims a numeric agreement with no responses present, and a report that would
pass LLM self-consistency off as human inter-annotator agreement.

The CLI is exercised as a subprocess because the gate's contract is its exit code and
its stderr reason list; the last class calls the checker in-process as well, so the
closed-vocabulary rule is enforced even if a runner never spawns python.
"""

from __future__ import annotations

import csv
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "tests" / "fixtures" / "broken"
TAXONOMY = ROOT / "taxonomy" / "root_cause_v1.jsonl"
RECORDS = ROOT / "derived" / "records.jsonl"
sys.path.insert(0, str(ROOT / "scripts"))

import validate_taxonomy as taxgate  # noqa: E402

# A category id that the closed vocabulary must never contain.
INVENTED_LEAF = "RC-999"


def run(script, *args):
    return subprocess.run([sys.executable, str(ROOT / "scripts" / script), *args],
                          capture_output=True, text=True)


def tax_args(tax, assign):
    return ["--root", str(ROOT), "--taxonomy", str(tax), "--assignments", str(assign),
            "--records", str(RECORDS)]


def load_fixture(name: str) -> dict:
    return json.loads((FIX / name).read_text(encoding="utf-8"))


def record_ids() -> set:
    return {json.loads(line)["id"] for line in
            RECORDS.read_text(encoding="utf-8").splitlines() if line.strip()}


class TaxonomyFixturesAreRejected(unittest.TestCase):
    def test_clean_run_passes(self):
        r = run("validate_taxonomy.py", "--root", str(ROOT))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_impact_written_as_root_cause_fails(self):
        r = run("validate_taxonomy.py", *tax_args(FIX / "taxonomy_impact_as_cause.jsonl",
                                                  FIX / "assignments_ok.jsonl"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("impact language in root-cause field", r.stderr, r.stderr)
        self.assertTrue("RC-XX" in r.stderr or "RC-01" in r.stderr, r.stderr)

    def test_primitive_written_as_root_cause_fails(self):
        r = run("validate_taxonomy.py", *tax_args(FIX / "taxonomy_primitive_as_cause.jsonl",
                                                  FIX / "assignments_ok.jsonl"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("primitive language in root-cause field", r.stderr, r.stderr)

    def test_unjustified_swc_map_fails(self):
        r = run("validate_taxonomy.py", *tax_args(FIX / "taxonomy_unjustified_swc.jsonl",
                                                  FIX / "assignments_ok.jsonl"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("has no justification", r.stderr, r.stderr)

    def test_invented_swc_identifier_fails(self):
        r = run("validate_taxonomy.py", *tax_args(FIX / "taxonomy_invented_swc.jsonl",
                                                  FIX / "assignments_ok.jsonl"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("has not verified", r.stderr, r.stderr)

    def test_map_without_justification_or_no_map_fails(self):
        r = run("validate_taxonomy.py", *tax_args(FIX / "taxonomy_no_map_no_reason.jsonl",
                                                  FIX / "assignments_ok.jsonl"))
        self.assertEqual(r.returncode, 1)
        self.assertTrue("no_map without a reason" in r.stderr
                        or "no entries and no explicit no_map" in r.stderr, r.stderr)

    def test_missing_exclusion_rule_fails(self):
        r = run("validate_taxonomy.py", *tax_args(FIX / "taxonomy_no_exclusions.jsonl",
                                                  FIX / "assignments_ok.jsonl"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("at least two exclusion rules", r.stderr, r.stderr)

    def test_assignment_to_unknown_category_fails(self):
        r = run("validate_taxonomy.py", *tax_args(FIX / "taxonomy_valid.jsonl",
                                                  FIX / "assignments_unknown_category.jsonl"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("outside the closed vocabulary", r.stderr, r.stderr)

    def test_assignment_for_unknown_record_fails(self):
        r = run("validate_taxonomy.py", *tax_args(FIX / "taxonomy_valid.jsonl",
                                                  FIX / "assignments_unknown_record.jsonl"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("unknown record id", r.stderr, r.stderr)

    def test_unlabelled_without_reason_fails(self):
        r = run("validate_taxonomy.py", *tax_args(FIX / "taxonomy_valid.jsonl",
                                                  FIX / "assignments_unlabelled_no_reason.jsonl"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("unlabelled without a reason", r.stderr, r.stderr)

    def test_exclusive_labels_together_fails(self):
        r = run("validate_taxonomy.py", *tax_args(FIX / "taxonomy_valid.jsonl",
                                                  FIX / "assignments_exclusive_pair.jsonl"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("mutually exclusive", r.stderr, r.stderr)

    def test_evidence_claim_contradicting_the_floor_fails(self):
        r = run("validate_taxonomy.py", *tax_args(FIX / "taxonomy_valid.jsonl",
                                                  FIX / "assignments_evidence_mismatch.jsonl"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("contradicts", r.stderr, r.stderr)

    def test_facet_must_not_be_assignable(self):
        r = run("validate_taxonomy.py", *tax_args(FIX / "taxonomy_facet_assignable.jsonl",
                                                  FIX / "assignments_ok.jsonl"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("facets are not assignable", r.stderr, r.stderr)

    def test_check_regenerates_byte_identical_outputs(self):
        r = run("validate_taxonomy.py", "--root", str(ROOT), "--check")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


class IAAGuessesAreRejected(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_iaa_report_claiming_numbers_without_responses_is_rejected(self):
        empty = self.tmp / "responses"
        empty.mkdir()
        bad = load_fixture("iaa_report_measured_without_responses.json")
        p = self.tmp / "report.json"
        p.write_text(json.dumps(bad), encoding="utf-8")
        r = run("iaa_statistics.py", "--audit-report", str(p), "--responses", str(empty))
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("no completed rows", r.stderr, r.stderr)

    def test_iaa_report_passing_llm_self_consistency_off_as_human_is_rejected(self):
        resp = self.tmp / "responses"
        resp.mkdir()
        rows = [
            {"annotator_id": "model-run-a", "annotator_kind": "llm_self_consistency",
             "record_id": "r1", "rc_primary": "RC-01", "severity_tier": "2", "evidence_ceiling": "L2"},
            {"annotator_id": "model-run-b", "annotator_kind": "llm_self_consistency",
             "record_id": "r1", "rc_primary": "RC-01", "severity_tier": "2", "evidence_ceiling": "L2"},
            {"annotator_id": "model-run-a", "annotator_kind": "llm_self_consistency",
             "record_id": "r2", "rc_primary": "RC-02", "severity_tier": "1", "evidence_ceiling": "L2"},
            {"annotator_id": "model-run-b", "annotator_kind": "llm_self_consistency",
             "record_id": "r2", "rc_primary": "RC-02", "severity_tier": "1", "evidence_ceiling": "L2"},
        ]
        fields = list(rows[0])
        with open(resp / "runs.csv", "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=fields)
            w.writeheader()
            w.writerows(rows)
        bad = load_fixture("iaa_report_llm_as_iaa.json")
        p = self.tmp / "report.json"
        p.write_text(json.dumps(bad), encoding="utf-8")
        r = run("iaa_statistics.py", "--audit-report", str(p), "--responses", str(resp))
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("self-consistency", r.stderr, r.stderr)


class ShippedClaimsAreHonest(unittest.TestCase):
    def test_shipped_iaa_status_says_not_measured(self):
        doc = json.loads((ROOT / "reports" / "iaa_status.json").read_text(encoding="utf-8"))
        self.assertIs(doc["measured"], False)
        self.assertTrue(doc["measured_reason"])
        # carried over verbatim from the original file; it is a tautology, kept so the
        # assertion list matches the pre-conversion version one for one.
        self.assertNotIn("measured", ("true", True))

    def test_taxonomy_is_not_claimed_as_a_community_standard(self):
        for name in ("root_cause_v1.md", "derivation_log.md"):
            with self.subTest(name):
                low = (ROOT / "taxonomy" / name).read_text(encoding="utf-8").lower()
                self.assertIn("community standard", low,
                              "%s must state the standard caveat" % name)
                self.assertTrue("project-local" in low or "not a community standard" in low)
                # the file must not assert adoption
                for phrase in ("is a community standard", "the community standard",
                               "adopted as a standard"):
                    self.assertNotIn(phrase, low.replace("not a community standard", ""),
                                     (name, phrase))


class ClosedVocabularyIsEnforcedInProcess(unittest.TestCase):
    """The fixtures above prove the CLI fails; these prove the checker itself rejects a
    label invented against the shipped vocabulary, without a subprocess."""

    @classmethod
    def setUpClass(cls):
        cls.record_ids = record_ids()
        cls.entries = taxgate.load_jsonl(TAXONOMY)
        cls.errors = []
        cls.taxonomy, cls.leaves = taxgate.check_taxonomy(list(cls.entries),
                                                          cls.record_ids, cls.errors)

    def test_shipped_vocabulary_is_self_consistent(self):
        self.assertEqual(self.errors, [], "; ".join(self.errors[:5]))
        self.assertTrue(self.leaves, "the vocabulary declares no assignable leaves")

    def test_invented_leaf_is_outside_the_closed_vocabulary(self):
        self.assertNotIn(INVENTED_LEAF, self.taxonomy)
        self.assertNotIn(INVENTED_LEAF, self.leaves)
        bad = [{"record_id": sorted(self.record_ids)[0], "labels": [INVENTED_LEAF],
                "evidence_level": "L2", "evidence_basis": "in-process probe row",
                "assignment_status": "provisional", "meets_minimum_evidence": {}}]
        errors = []
        taxgate.check_assignments(bad, self.taxonomy, self.leaves, self.record_ids, errors)
        self.assertTrue(any("outside the closed vocabulary" in e for e in errors), errors)


if __name__ == "__main__":
    unittest.main()
