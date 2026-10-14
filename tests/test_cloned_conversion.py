import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "work" / "cloned_conversion" / "staged_report_candidates.jsonl"
WEB_MANIFEST = ROOT / "work" / "new_sources_intake_manifest.json"


@unittest.skipUnless(STAGE.exists(), "staged report candidates unavailable (work directory is gitignored)")
class TestClonedConversionStage (unittest.TestCase):
    def setUp(self):
        self.rows = [json.loads(x) for x in STAGE.read_text(encoding="utf-8").splitlines() if x.strip()]

    def test_nonempty(self):
        self.assertGreater(len(self.rows), 0)

    def test_required_fields(self):
        required = {"candidate_id", "record_type", "source_id", "source_url",
                    "report_path", "report_file_name", "report_sha256",
                    "decision", "admitted", "verification_level", "evidence"}
        for row in self.rows:
            self.assertTrue(required.issubset(row.keys()), row.get("candidate_id"))

    def test_unique_ids(self):
        ids = [r["candidate_id"] for r in self.rows]
        self.assertEqual(len(ids), len(set(ids)))

    def test_decision_and_level(self):
        for row in self.rows:
            self.assertEqual(row["decision"], "CANDIDATE_REPORT_ONLY")
            self.assertEqual(row["verification_level"], "L0")
            self.assertFalse(row["admitted"])

    def test_counts_match_inventory(self):
        from collections import Counter
        counts = Counter(r["source_id"] for r in self.rows)
        self.assertEqual(counts["halborn_public_reports"], 282)
        self.assertEqual(counts["oak_security_audit_reports"], 316)
        self.assertEqual(counts["coinfabrik_audit_reports"], 68)

    def test_sha256_lengths(self):
        for row in self.rows:
            self.assertEqual(len(row["report_sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
