#!/usr/bin/env python3
"""Tests for scripts/check_rights_consistency.py (spec item 5 rights gate).

Each broken fixture under tests/fixtures/broken/ must make the gate exit
non-zero AND report the specific reason code it is designed to catch; a
fixture that only produces unrelated noise would pass this test silently, so
both the exit code and the code are asserted.

The good fixture under tests/fixtures/good/ is the reconciled shape of the
same inputs: it must exit 0, which proves the checks are not vacuous.

Run:  python -m unittest tests.test_rights_gate
"""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from vlun_io import read_jsonl  # noqa: E402

GATE = ROOT / "scripts" / "check_rights_consistency.py"
BROKEN = ROOT / "tests" / "fixtures" / "broken"
GOOD = ROOT / "tests" / "fixtures" / "good"


def run_gate(fixture: Path) -> tuple[int, dict]:
    proc = subprocess.run(
        [sys.executable, str(GATE), "--root", str(fixture), "--partial",
         "--quiet", "--json"],
        capture_output=True, text=True, encoding="utf-8", errors="replace")
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        raise AssertionError(
            f"gate printed no JSON for {fixture}\n"
            f"stdout={proc.stdout[:500]!r}\nstderr={proc.stderr[:900]!r}")
    return proc.returncode, payload


def codes(payload: dict) -> set[str]:
    return {r["code"] for r in payload.get("reasons", [])}


class V4StatusesAreReconciled(unittest.TestCase):
    """The layers must state one licence status per source."""

    def test_sources_records_and_registry_agree(self) -> None:
        decision = {s["source_id"]: s["license_status"] for s in
                    json.loads((ROOT / "V4" / "licensing.json")
                               .read_text(encoding="utf-8"))["sources"]}
        sources = {r["source_id"]: r["license_status"] for r in
                   json.loads((ROOT / "V4" / "sources.json").read_text(encoding="utf-8"))}
        self.assertEqual(sources, decision)
        registry = {r["source_id"]: r["license_status_required"] for r in
                    json.loads((ROOT / "distribution_v1" / "rights_source_registry.json")
                               .read_text(encoding="utf-8"))["sources"]}
        self.assertEqual({k: registry[k] for k in decision}, decision)
        per_record = set()
        for row in read_jsonl(ROOT / "jsonl_v4" / "findings.jsonl"):
            per_record.add((row["source_id"], row["license_status"]))
        self.assertEqual({sid for sid, _ in per_record}, set(decision))
        for sid, status in per_record:
            self.assertEqual(status, decision[sid], sid)
        self.assertTrue(all("status_drift_in_published_records" not in r or
                            not r["status_drift_in_published_records"]
                            for r in json.loads((ROOT / "distribution_v1"
                                                / "rights_source_registry.json")
                                               .read_text(encoding="utf-8"))["sources"]))

    def test_no_source_ships_a_placeholder_status(self) -> None:
        for row in read_jsonl(ROOT / "jsonl_v4" / "findings.jsonl"):
            self.assertNotEqual(row.get("license"), "unknown", row.get("record_id"))
            self.assertNotEqual(row.get("license_status"), "unknown")
            self.assertIn("rights_decision", row)


class RightsGateBrokenFixtures(unittest.TestCase):
    def test_copied_unlicensed_source_fails(self) -> None:
        code, payload = run_gate(BROKEN / "copied_unlicensed_source")
        self.assertEqual(code, 1, payload)
        self.assertIn("DIST_FORBIDDEN_CODE_PRESENT", codes(payload))

    def test_two_licence_statuses_for_one_source_fails(self) -> None:
        code, payload = run_gate(BROKEN / "contradictory_licence")
        self.assertEqual(code, 1, payload)
        self.assertIn("LICENCE_STATUS_CONTRADICTION", codes(payload))
        self.assertIn("UNKNOWN_MASKS_DECLARED_LICENCE", codes(payload))
        oak = [r for r in payload["reasons"]
               if r.get("source_id") == "oak_security_audit_reports"]
        self.assertTrue(oak, "the Oak Security CC BY-ND case must be named")

    def test_attribution_free_digest_fails(self) -> None:
        code, payload = run_gate(BROKEN / "attribution_free_digest")
        self.assertEqual(code, 1, payload)
        self.assertIn("DIGEST_MISSING_ATTRIBUTION", codes(payload))

    def test_bad_hash_fails(self) -> None:
        code, payload = run_gate(BROKEN / "bad_hash")
        self.assertEqual(code, 1, payload)
        self.assertIn("INVALID_SHA256", codes(payload))
        self.assertIn("MANIFEST_HASH_MISMATCH", codes(payload))

    def test_an_abbreviated_commit_may_not_be_filed_as_immutable(self) -> None:
        """A 7-character prefix is what a report stated, not a pin."""
        code, payload = run_gate(BROKEN / "abbrev_commit_as_immutable")
        self.assertEqual(code, 1, payload)
        self.assertIn("INVALID_COMMIT_REF", codes(payload))
        row = next(json.loads(l) for l in (BROKEN / "abbrev_commit_as_immutable" /
                                           "distribution_v1" /
                                           "records_v1_withheld_pointers.jsonl")
                   .read_text(encoding="utf-8").splitlines() if l.strip())
        self.assertEqual(row["immutable_reference"]["vulnerable_commit"], "64d3a2d")
        # and the projection this repo actually ships keeps them apart
        live = next(json.loads(l) for l in
                    (ROOT / "distribution_v1" / "records_v4_withheld_pointers.jsonl")
                    .read_text(encoding="utf-8").splitlines() if l.strip())
        for key, value in (live.get("immutable_reference") or {}).items():
            self.assertRegex(str(value), r"^[0-9a-f]{40}$", key)
        self.assertNotIn("64d3a2d", json.dumps(live.get("immutable_reference") or {}))

    def test_reasons_are_machine_readable(self) -> None:
        _code, payload = run_gate(BROKEN / "copied_unlicensed_source")
        self.assertEqual(payload["exit_code"], 1)
        self.assertTrue(payload["reasons"])
        for r in payload["reasons"]:
            self.assertIn("code", r)
            self.assertIn("artifact", r)
            self.assertIn("detail", r)
        self.assertTrue(payload["policy_is_default_not_clearance"])
        self.assertEqual(payload["rights_transformation_version"], "rights-1.0")


class RightsGateGoodFixture(unittest.TestCase):
    def test_reconciled_fixture_passes(self) -> None:
        code, payload = run_gate(GOOD)
        self.assertEqual(code, 0, json.dumps(payload, indent=2)[:2000])
        self.assertEqual(payload["reasons"], [])


class RightsGateLiveTree(unittest.TestCase):
    """Read-only checks against the real repository."""

    def test_gate_is_runnable_and_reports_the_known_findings(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(GATE), "--quiet", "--json"],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", cwd=str(ROOT))
        payload = json.loads(proc.stdout)
        self.assertEqual(proc.returncode, 0, json.dumps(payload)[:1200])
        found = {r["code"] for r in payload["reasons"]}
        # the V4 statuses were reconciled into V4/licensing.json; a contradiction
        # is now a failure, not a standing finding, and the gate must say so
        self.assertNotIn("LICENCE_STATUS_CONTRADICTION", found)
        self.assertNotIn("UNKNOWN_MASKS_DECLARED_LICENCE", found)
        self.assertNotIn("POLICY_FRAMING_MISSING", found)
        # what is still true is reported as a limitation, not silently dropped
        limits = {l["code"] for l in payload.get("noted_limitations", [])}
        self.assertIn("UPSTREAM_HASH_NOT_RECORDED", limits)

    def test_distribution_view_carries_no_copied_expression(self) -> None:
        view = ROOT / "distribution_v1"
        if not view.is_dir():
            self.skipTest("distribution_v1 not built")
        proc = subprocess.run(
            [sys.executable, str(GATE), "--quiet", "--json"],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", cwd=str(ROOT))
        reasons = json.loads(proc.stdout)["reasons"]
        copied = [r for r in reasons if r["code"] in (
            "DIST_FORBIDDEN_CODE_PRESENT", "DIST_COPIED_PROSE_OVER_QUOTA",
            "DIST_PERSONAL_DATA_PRESENT", "DIGEST_VERBATIM_OVERLAP",
            "HASH_MISMATCH", "MANIFEST_HASH_MISMATCH")]
        self.assertEqual(copied, [], f"the view must be clean: {copied}")

    def test_inventory_counts_are_recomputed_not_typed(self) -> None:
        inv_path = ROOT / "reports" / "rights_inventory.json"
        if not inv_path.is_file():
            self.skipTest("inventory not generated")
        inv = json.loads(inv_path.read_text(encoding="utf-8"))
        per_layer = sum(sum(c.values())
                        for c in inv["totals_by_layer"].values())
        total = sum(inv["totals_by_class"]["expressive_items"].values())
        self.assertEqual(per_layer, total)
        self.assertEqual(inv["scan"]["tracked_files"],
                         len(subprocess.run(
                             ["git", "ls-files"], cwd=str(ROOT),
                             capture_output=True, text=True).stdout.split()))
        # the audit must not be limited to the 424 self-flagged v1 rows
        self.assertGreater(len(inv["totals_by_layer"]), 40)


if __name__ == "__main__":
    unittest.main()
