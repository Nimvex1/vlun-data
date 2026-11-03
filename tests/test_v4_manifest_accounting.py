"""Regression tests for the V4 manifest count domains (5,270 vs 5,268).

Run:  python -m unittest tests.test_v4_manifest_accounting

The old manifest reported `verification_levels: {"L0": len(findings)}` --
the candidate count (5,270) -- next to `admitted` (5,268). The two duplicate
candidates were preserved in duplicate_ledger.jsonl but silently absent from
the level distribution's declared domain. These tests exercise the builder
functions directly on temp fixtures so the domains cannot drift again.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import register_v4 as R  # noqa: E402


def _finding(cid: str, title: str = "Reentrancy in withdraw",
             source_id: str = "oak_security_audit_reports",
             report_path: str = "Drop/report.pdf",
             commit: str = "a" * 40,
             severity: str | None = "High") -> dict:
    row = {
        "candidate_id": cid,
        "title": title,
        "finding_title": title,
        "source_id": source_id,
        "report_path": report_path,
        "affected_repository": "https://github.com/example/protocol",
        "source_url": "https://github.com/example/protocol",
        "vulnerable_commit": commit,
        "language": "solidity",
        "normalized_vulnerability_class": "unknown",
        "verification_level": "L0",
    }
    if severity is not None:
        row["original_severity"] = severity
    return row


def _existing(cid: str, title: str = "Reentrancy in withdraw",
              commit: str = "a" * 40) -> dict:
    return {
        "candidate_id": cid,
        "title": title,
        "source_url": "https://github.com/example/protocol",
        "affected_repository": "https://github.com/example/protocol",
        "vulnerable_commit": commit,
        "verification_level": "L1",
    }


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")


class TestPartitionFindings(unittest.TestCase):
    def test_within_extracted_duplicate_is_preserved_with_duplicate_of(self):
        findings = [_finding("cand-a"), _finding("cand-b")]
        admitted, quarantined, duplicates, ledger = R.partition_findings(
            findings, [])
        self.assertEqual([r["candidate_id"] for r in admitted], ["cand-a"])
        self.assertEqual(quarantined, [])
        self.assertEqual(len(duplicates), 1)
        self.assertEqual(duplicates[0]["candidate_id"], "cand-b")
        self.assertEqual(duplicates[0]["duplicate_of"], "cand-a")
        self.assertEqual(len(ledger), len(findings))
        self.assertEqual([r["decision"] for r in ledger],
                         ["ADMITTED", "DUPLICATE"])

    def test_existing_match_duplicate_points_at_existing_candidate(self):
        finding = _finding("cand-new")
        admitted, quarantined, duplicates, ledger = R.partition_findings(
            [finding], [_existing("existing-1")])
        self.assertEqual(admitted, [])
        self.assertEqual(len(duplicates), 1)
        self.assertEqual(duplicates[0]["duplicate_of"], "existing-1")
        self.assertEqual(ledger[0]["decision"], "DUPLICATE")

    def test_missing_core_fields_are_quarantined_not_admitted(self):
        findings = [_finding("cand-a"), _finding("cand-b", severity=None)]
        admitted, quarantined, duplicates, ledger = R.partition_findings(
            findings, [])
        self.assertEqual(len(admitted), 1)
        self.assertEqual(len(quarantined), 1)
        self.assertEqual(quarantined[0]["candidate_id"], "cand-b")
        self.assertEqual(len(ledger), 2)

    def test_temp_jsonl_fixture_round_trip(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "extracted_findings.jsonl"
            _write_jsonl(path, [_finding("cand-a"), _finding("cand-b")])
            findings = R.load_jsonl(path)
        admitted, quarantined, duplicates, ledger = R.partition_findings(
            findings, [])
        self.assertEqual((len(admitted), len(quarantined), len(duplicates),
                          len(ledger)), (1, 0, 1, 2))


class TestManifestDomains(unittest.TestCase):
    def _buckets(self, findings, existing=None):
        return R.partition_findings(findings, existing or [])

    def test_verification_levels_are_over_admitted_not_candidates(self):
        findings = [_finding("cand-a"), _finding("cand-b")]
        admitted, quarantined, duplicates, ledger = self._buckets(findings)
        manifest = R.build_manifest(findings, admitted, quarantined,
                                    duplicates, ledger, staged_count=0)
        self.assertEqual(manifest["candidates"], 2)
        self.assertEqual(manifest["admitted"], 1)
        self.assertEqual(manifest["duplicates"], 1)
        self.assertEqual(manifest["quarantined"], 0)
        self.assertEqual(manifest["verification_levels"], {"L0": 1})
        self.assertEqual(manifest["candidate_verification_levels"], {"L0": 2})
        self.assertEqual(sum(manifest["verification_levels"].values()),
                         manifest["admitted"])
        self.assertEqual(sum(manifest["candidate_verification_levels"].values()),
                         manifest["candidates"])

    def test_candidate_total_is_admitted_plus_duplicates_plus_quarantined(self):
        findings = [_finding("cand-a"), _finding("cand-b"),
                    _finding("cand-c", severity=None)]
        admitted, quarantined, duplicates, ledger = self._buckets(findings)
        manifest = R.build_manifest(findings, admitted, quarantined,
                                    duplicates, ledger, staged_count=0)
        self.assertEqual(
            manifest["candidates"],
            manifest["admitted"] + manifest["duplicates"]
            + manifest["quarantined"])
        self.assertEqual(manifest["candidates"], manifest["candidate_ledger"])
        self.assertEqual(manifest["extracted_findings"], manifest["candidates"])

    def test_manifest_refuses_buckets_that_do_not_sum(self):
        findings = [_finding("cand-a"), _finding("cand-b")]
        admitted, quarantined, duplicates, ledger = self._buckets(findings)
        with self.assertRaises(RuntimeError):
            R.build_manifest(findings, admitted, quarantined, duplicates,
                             ledger[:-1], staged_count=0)


class TestCommittedDuplicateLedger(unittest.TestCase):
    """The committed duplicate links resolve and are never admitted twice."""

    def test_duplicate_of_targets_exist_in_candidate_ledger(self):
        cand_ids = {json.loads(line)["candidate_id"] for line in
                    (ROOT / "derived_v4" / "candidate_ledger.jsonl")
                    .open(encoding="utf-8") if line.strip()}
        rows = [json.loads(line) for line in
                (ROOT / "derived_v4" / "duplicate_ledger.jsonl")
                .open(encoding="utf-8") if line.strip()]
        self.assertTrue(rows)
        for row in rows:
            self.assertTrue(row.get("duplicate_of"), row.get("candidate_id"))
            self.assertIn(row["duplicate_of"], cand_ids)
            self.assertNotEqual(row["candidate_id"], row["duplicate_of"])


def _line_count(path):
    with open(path, encoding="utf-8") as fh:
        return sum(1 for line in fh if line.strip())


class TestCommittedManifestAccounting(unittest.TestCase):
    """Regression tests on the committed layers for the 5,270-vs-5,268 bug.

    The shipped manifest declared `verification_levels: {"L0": 5270}` next to
    `admitted: 5268`: the level distribution was over the candidate domain
    (extracted findings, incl. 2 duplicates kept in duplicate_ledger.jsonl)
    while its neighbouring count was the admitted domain. These tests pin
    every declared domain to its committed layer file so the mismatch cannot
    reappear.
    """

    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(
            (ROOT / "derived_v4" / "manifest.json").read_text(encoding="utf-8"))

    def test_verification_levels_sum_over_admitted_domain(self):
        m = self.manifest
        self.assertEqual(sum(m["verification_levels"].values()), m["admitted"])
        self.assertEqual(
            m["admitted"], _line_count(ROOT / "derived_v4" / "admitted_ledger.jsonl"))
        self.assertEqual(
            m["admitted"], _line_count(ROOT / "jsonl_v4" / "findings.jsonl"))

    def test_candidate_verification_levels_sum_over_candidate_domain(self):
        m = self.manifest
        self.assertEqual(
            sum(m["candidate_verification_levels"].values()), m["candidates"])
        self.assertEqual(
            m["candidates"],
            _line_count(ROOT / "derived_v4" / "candidate_ledger.jsonl"))
        self.assertEqual(m["candidates"], m["candidate_ledger"])
        self.assertEqual(m["candidates"], m["extracted_findings"])

    def test_bucket_partitions_sum_to_candidates(self):
        m = self.manifest
        self.assertEqual(
            m["candidates"], m["admitted"] + m["duplicates"] + m["quarantined"])
        self.assertEqual(
            m["duplicates"],
            _line_count(ROOT / "derived_v4" / "duplicate_ledger.jsonl"))
        self.assertEqual(
            m["quarantined"],
            _line_count(ROOT / "derived_v4" / "quarantined_ledger.jsonl"))

    def test_documented_duplicates_are_deferred_by_exact_id(self):
        """The 2 candidates dropped from admitted are auditable, not implied."""
        rows = {}
        with open(ROOT / "derived_v4" / "duplicate_ledger.jsonl",
                  encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    rec = json.loads(line)
                    rows[rec["candidate_id"]] = rec
        expected = {
            "oak_security_audit_reports:d02ce086b861":
                "oak_security_audit_reports:14c035ceccf6",
            "oak_security_audit_reports:8dcf7824fc76":
                "oak_security_audit_reports:c1f30274307c",
        }
        self.assertEqual(sorted(rows), sorted(expected))
        for cid, dup_of in expected.items():
            self.assertIn(cid, rows, f"{cid} missing from duplicate_ledger")
            self.assertEqual(rows[cid]["duplicate_of"], dup_of)
            self.assertEqual(rows[cid]["decision"], "DUPLICATE")
            # never admitted: absent from the admitted layer and its ledger
            # decision is DUPLICATE
            admitted_ids = set()
            with open(ROOT / "derived_v4" / "admitted_ledger.jsonl",
                      encoding="utf-8") as fh:
                for line in fh:
                    if line.strip():
                        admitted_ids.add(json.loads(line)["candidate_id"])
            with open(ROOT / "jsonl_v4" / "findings.jsonl",
                      encoding="utf-8") as fh:
                for line in fh:
                    if line.strip():
                        admitted_ids.add(json.loads(line)["candidate_id"])
            self.assertNotIn(cid, admitted_ids)
        decisions = {}
        with open(ROOT / "derived_v4" / "candidate_ledger.jsonl",
                  encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    row = json.loads(line)
                    decisions[row["candidate_id"]] = row["decision"]
        for cid in expected:
            self.assertEqual(decisions[cid], "DUPLICATE")
            self.assertEqual(decisions[expected[cid]], "ADMITTED")

    def test_manifest_rebuild_is_byte_deterministic(self):
        first = R.manifest_serialise(
            R.build_manifest_from_committed_layers(ROOT)[1])
        second = R.manifest_serialise(
            R.build_manifest_from_committed_layers(ROOT)[1])
        self.assertEqual(first.encode("utf-8"), second.encode("utf-8"))
        # and it reproduces the shipped manifest exactly
        self.assertEqual(
            json.loads(first), self.manifest)


if __name__ == "__main__":
    unittest.main(verbosity=2)