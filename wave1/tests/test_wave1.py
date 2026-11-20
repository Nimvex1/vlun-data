"""Stdlib-only structural tests for wave1/. Run: python -m unittest discover -s wave1/tests"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

WAVE1 = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WAVE1 / "scripts"))

from _common import ROOT, WAVE1 as COMMON_WAVE1, guard_wave1, load_registry, read_jsonl, sha256_file  # noqa: E402


class TestConfinement(unittest.TestCase):
    def test_root_paths_agree(self):
        self.assertEqual(COMMON_WAVE1.resolve(), WAVE1.resolve())

    def test_guard_rejects_canonical_path(self):
        with self.assertRaises(PermissionError):
            guard_wave1(ROOT / "jsonl" / "findings.jsonl")

    def test_guard_accepts_wave1_path(self):
        p = guard_wave1(WAVE1 / "04_admitted" / "x.jsonl")
        self.assertTrue(str(p).startswith(str(WAVE1)))


class TestRegistry(unittest.TestCase):
    def test_registry_not_empty_and_unique(self):
        rows = list(read_jsonl(WAVE1 / "01_dedup" / "registry.jsonl"))
        self.assertGreater(len(rows), 1000)
        keys = [r["key"] for r in rows]
        self.assertEqual(len(keys), len(set(keys)), "registry keys must be unique")
        self.assertTrue(all(r.get("layer") for r in rows))

    def test_registry_has_required_layers(self):
        reg = load_registry()
        layers = {r.get("layer") for r in reg.values()}
        self.assertTrue({"v1", "v2.2", "V3", "Vbeta", "V4", "Prove"}.issubset(layers))

    def test_mitigation_occupancies_present(self):
        reg = load_registry()
        n = sum(1 for k in reg if k.startswith("mitigation_issue:2024-02-renft-mitigation-findings:"))
        self.assertGreaterEqual(n, 1)

    def test_certora_pointers_are_unique_keys(self):
        reg = load_registry()
        cert = [k for k in reg if k.startswith("certora_rule:certora-reports:")]
        self.assertEqual(len(cert), 200)


class TestAdmitted(unittest.TestCase):
    def test_admitted_rows_have_dedup_keys(self):
        base = WAVE1 / "04_admitted"
        if not base.exists():
            self.skipTest("no admitted rows yet")
        for p in base.rglob("*.jsonl"):
            for row in read_jsonl(p):
                self.assertTrue(row.get("dedup_keys"), f"{p}: missing dedup_keys")
                self.assertFalse(any(len(str(v)) > 1000 for v in row.values()), f"{p}: prose leak")


class TestSemanticPurity(unittest.TestCase):
    def test_label_domains_contract_exists(self):
        p = WAVE1 / "00_governance" / "label_domains.json"
        self.assertTrue(p.exists())
        data = json.loads(p.read_text(encoding="utf-8"))
        self.assertIn("patch_verification_outcome", data["domains"])
        self.assertIn("formal_property", data["domains"])
        self.assertTrue(data["families"]["J_verified_patch"]["require_l6_artefact"])

    def test_g_has_no_severity_labels(self):
        p = WAVE1 / "benchmark_wave1" / "G_patch_verification.jsonl"
        if not p.exists():
            self.skipTest("G not built yet")
        for row in read_jsonl(p):
            self.assertNotIn(str(row.get("label")), {"high", "low"})
            self.assertIn(str(row.get("label")),
                          {"mitigation_confirmed", "unmitigated_or_regression"})

    def test_j_requires_l6_artefact(self):
        import re
        sha40 = re.compile(r"^[0-9a-fA-F]{40}$")
        p = WAVE1 / "benchmark_wave1" / "J_verified_patch.jsonl"
        if not p.exists():
            self.skipTest("J not built yet")
        for row in read_jsonl(p):
            ex = row.get("execution") or {}
            self.assertEqual(str(ex.get("level", "")).upper(), "L6")
            self.assertRegex(str(ex.get("vulnerable_sha", "")), sha40)
            self.assertRegex(str(ex.get("fixed_sha", "")), sha40)
            self.assertTrue(ex.get("violation_reproduced"))
            self.assertTrue(ex.get("blocked_on_fixed"))
            self.assertTrue(str(ex.get("result_artefact", "")))


class TestPresent(unittest.TestCase):
    def test_canonical_hashes_match(self):
        p = WAVE1 / "00_governance" / "PRESENT.md.json"
        self.assertTrue(p.exists())
        data = json.loads(p.read_text(encoding="utf-8"))
        for rel, expected in data["canonical_sha256"].items():
            self.assertEqual(sha256_file(ROOT / rel), expected, f"drift in {rel}")


if __name__ == "__main__":
    unittest.main()
