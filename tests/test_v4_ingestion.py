import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
V4_JSONL = ROOT / "jsonl_v4" / "findings.jsonl"
V4_SOURCES = ROOT / "jsonl_v4" / "sources.jsonl"
DER = ROOT / "derived_v4"
CAND = DER / "candidate_ledger.jsonl"
ADM = DER / "admitted_ledger.jsonl"
QUAR = DER / "quarantined_ledger.jsonl"
DUP = DER / "duplicate_ledger.jsonl"

class TestV4Ingestion(unittest.TestCase):
    def setUp(self):
        self.findings = [json.loads(x) for x in V4_JSONL.read_text(encoding="utf-8").splitlines() if x.strip()]
        self.cand = [json.loads(x) for x in CAND.read_text(encoding="utf-8").splitlines() if x.strip()]
        self.adm = [json.loads(x) for x in ADM.read_text(encoding="utf-8").splitlines() if x.strip()]
        self.quar = [json.loads(x) for x in QUAR.read_text(encoding="utf-8").splitlines() if x.strip()]
        self.dup = [json.loads(x) for x in DUP.read_text(encoding="utf-8").splitlines() if x.strip()]

    def test_nonempty(self):
        self.assertGreater(len(self.findings), 0)
        self.assertGreater(len(self.cand), 0)

    def test_required_fields(self):
        required = {"candidate_id", "record_type", "source_id", "source_url",
                    "report_path", "report_file_name", "report_sha256",
                    "title", "original_severity", "verification_level",
                    "source_pointer", "source_page"}
        for row in self.findings:
            self.assertTrue(required.issubset(row.keys()), row.get("candidate_id"))

    def test_unique_ids(self):
        ids = [r["candidate_id"] for r in self.findings]
        self.assertEqual(len(ids), len(set(ids)))

    def test_source_hashes(self):
        import hashlib
        source_dirs = {
            "halborn_public_reports": "halborn_reports",
            "oak_security_audit_reports": "oak_audit_reports",
            "coinfabrik_audit_reports": "coinfabrik_reports",
        }
        checked = 0
        missing = []
        for row in self.findings:
            self.assertEqual(len(row["report_sha256"]), 64)
            d = source_dirs.get(row.get("source_id"))
            if not d:
                continue
            p = ROOT / "work" / "new_sources" / d / row["report_path"]
            if not p.is_file():
                missing.append(str(p))
                continue
            h = hashlib.sha256()
            with open(p, "rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""):
                    h.update(chunk)
            self.assertEqual(h.hexdigest(), row["report_sha256"],
                             row.get("candidate_id"))
            checked += 1
        if missing and checked == 0:
            self.skipTest("report files unavailable (work/ is gitignored)")

    def test_provenance_complete(self):
        for row in self.findings:
            self.assertTrue(row.get("source_pointer"))
            self.assertTrue(row.get("source_page"))
            self.assertTrue(row.get("source_url"))

    def test_count_consistency(self):
        self.assertEqual(len(self.cand), len(self.adm) + len(self.quar) + len(self.dup))
        self.assertEqual(len(self.adm), len(self.findings))

    def test_duplicate_ledger(self):
        for row in self.dup:
            self.assertTrue(row.get("duplicate_of"))

    def test_preserve_original_labels(self):
        for row in self.findings:
            self.assertEqual(row.get("severity_reported"), row.get("original_severity"))
            self.assertIsNotNone(row.get("title"))

    def test_manifest_counts(self):
        manifest = json.loads((ROOT / "derived_v4" / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["extracted_findings"],
                         len(self.findings) + len(self.quar) + len(self.dup))
        self.assertEqual(manifest["admitted"], len(self.adm))
        self.assertEqual(manifest["quarantined"], len(self.quar))
        self.assertEqual(manifest["duplicates"], len(self.dup))

if __name__ == "__main__":
    unittest.main()
