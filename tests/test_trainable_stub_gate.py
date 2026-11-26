"""Unit tests for the Option A zero-stub audit gate.

The audit JSON is schema-driven; these tests prove the hard assertion fails on
stub rows in trainable/benchmark tables but tolerates the same rows in the
explicit governance/quarantine-ledger and test-fixture roles.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts import verify_audit as va


def _file(path: str, role: str, stubs: int) -> dict:
    return {
        "path": path,
        "table_role": role,
        "buckets": {
            "FULLY_TRAINABLE": 10,
            "PARTIAL_TEXT_NO_CODE": 0,
            "METADATA_ONLY_STUB": stubs,
        },
    }


def _audit(files: list[dict]) -> dict:
    return {
        "definitions": {"table_roles": {"trainable_or_benchmark": {},
                                        "governance_or_quarantine_ledger": {},
                                        "test_fixture": {}}},
        "summary": {"table_roles": {
            "trainable_or_benchmark": {
                "files": sum(1 for f in files
                             if f["table_role"] == "trainable_or_benchmark"),
                "METADATA_ONLY_STUB": sum(
                    f["buckets"]["METADATA_ONLY_STUB"] for f in files
                    if f["table_role"] == "trainable_or_benchmark"),
            },
        }},
        "files": files,
    }


class TestZeroTrainableStubGate(unittest.TestCase):
    def test_clean_trainable_table_passes(self) -> None:
        res = va.Results()
        res.passed("seed", "")
        files = [_file("derived/records.jsonl", "trainable_or_benchmark", 0)]
        va.check_zero_trainable_stubs(res, _audit(files), files)
        self.assertEqual(0, res.failed_count)

    def test_stub_in_trainable_table_fails(self) -> None:
        res = va.Results()
        res.passed("seed", "")
        files = [_file("benchmark/A.jsonl", "trainable_or_benchmark", 5)]
        va.check_zero_trainable_stubs(res, _audit(files), files)
        self.assertGreater(res.failed_count, 0)
        self.assertIn("zero stubs", " ".join(d for _, d, _ in res.records))

    def test_stub_in_ledger_or_fixture_is_allowed(self) -> None:
        res = va.Results()
        res.passed("seed", "")
        files = [
            _file("derived_v3/quarantine.jsonl", "governance_or_quarantine_ledger", 500),
            _file("tests/fixtures/broken/a.jsonl", "test_fixture", 2),
            _file("derived/records.jsonl", "trainable_or_benchmark", 0),
        ]
        va.check_zero_trainable_stubs(res, _audit(files), files)
        self.assertEqual(0, res.failed_count)

    def test_role_classification(self) -> None:
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
        from audit_trainable_vs_metadata import classify_table_role as role

        self.assertEqual("trainable_or_benchmark", role("derived/records.jsonl"))
        self.assertEqual("trainable_or_benchmark", role("benchmark/A.jsonl"))
        self.assertEqual("trainable_or_benchmark", role("training/canonical/a.jsonl"))
        self.assertEqual("governance_or_quarantine_ledger", role("derived_v3/quarantine.jsonl"))
        self.assertEqual("governance_or_quarantine_ledger", role("rights.jsonl"))
        self.assertEqual("governance_or_quarantine_ledger", role("wave1/00_governance/rights.jsonl"))
        self.assertEqual("test_fixture", role("tests/fixtures/broken/a.jsonl"))


class _NoMetadataOnlyGate(unittest.TestCase):
    """Re-derivation check: stale METADATA_ONLY tags in trainable rows."""

    def _run(self, rows_by_path: dict[str, list[dict]]) -> va.Results:
        files = [{"path": path, "table_role": role}
                 for path, (role, _rows) in rows_by_path.items()]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for path, (role, rows) in rows_by_path.items():
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(
                    "\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n",
                    encoding="utf-8", newline="\n")
            original = va.REPO_ROOT
            try:
                va.REPO_ROOT = root
                res = va.Results()
                va.check_no_metadata_only_in_trainable(res, files)
                return res
            finally:
                va.REPO_ROOT = original

    def test_hydrated_tags_pass(self) -> None:
        rows = [
            {"id": "a", "data_handling_policy": "FULL_INLINE_EXTRACTION"},
            {"id": "b", "data_handling_policy": "VERBATIM_HYDRATED"},
            {"id": "c", "redistribution": "INLINE_EVIDENCE_EXTRACTED"},
            {"id": "d", "extraction_mode": "QUARANTINED_POINTER"},
        ]
        res = self._run({"train/a.jsonl": ("trainable_or_benchmark", rows)})
        self.assertEqual(0, res.failed_count, str(res.records))

    def test_stale_policy_tag_in_trainable_file_fails(self) -> None:
        rows = [
            {"id": "a", "data_handling_policy": "METADATA_ONLY"},
            {"id": "b", "description": "fine"},
        ]
        res = self._run({"train/a.jsonl": ("trainable_or_benchmark", rows)})
        self.assertEqual(1, res.failed_count, str(res.records))
        self.assertIn("zero METADATA_ONLY", " ".join(d for _, d, _ in res.records))

    def test_boilerplate_in_trainable_file_fails(self) -> None:
        rows = [{"id": "a", "description":
                 "Full wording lives at the source; this dataset keeps metadata only (METADATA_ONLY)."}]
        res = self._run({"train/a.jsonl": ("trainable_or_benchmark", rows)})
        self.assertEqual(1, res.failed_count, str(res.records))

    def test_same_tag_allowed_in_ledger_and_fixture(self) -> None:
        stale = [{"id": "a", "data_handling_policy": "METADATA_ONLY"}]
        res = self._run({
            "derived_v3/quarantine.jsonl": ("governance_or_quarantine_ledger", stale),
            "tests/fixtures/broken/a.jsonl": ("test_fixture", stale),
            "train/a.jsonl": ("trainable_or_benchmark",
                              [{"id": "b", "data_handling_policy": "FULL_INLINE_EXTRACTION"}]),
        })
        self.assertEqual(0, res.failed_count, str(res.records))


if __name__ == "__main__":
    unittest.main()
