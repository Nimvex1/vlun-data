#!/usr/bin/env python3
"""Stdlib-only tests for the Vbeta layer.

    python Vbeta/tests/test_vbeta.py

Covers: decision-rule unit cases, gate invariants over built artefacts,
benchmark answer rebuildability, and PRESENT isolation sentinels.
Exit non-zero on any failure. Requires a prior `build_vbeta.py` run.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import vlun_vbeta as V  # noqa: E402


class TestDecide(unittest.TestCase):
    def test_import_needs_all_four(self):
        d, _ = V.decide({"kind": "finding", "severity_observed": "High",
                         "status_observed": "Fixed",
                         "link_observed": "https://x.example/a"})
        self.assertEqual(d, "IMPORT")

    def test_rejected_becomes_negative(self):
        d, _ = V.decide({"kind": "finding", "severity_observed": "High",
                         "status_observed": "Rejected",
                         "link_observed": "https://x.example/a"})
        self.assertEqual(d, "IMPORT_AS_NEGATIVE")

    def test_partial_becomes_unverified(self):
        d, _ = V.decide({"kind": "finding", "severity_observed": "High",
                         "status_observed": None,
                         "link_observed": "https://x.example/a"})
        self.assertEqual(d, "IMPORT_AS_UNVERIFIED")

    def test_pointer_becomes_research_only(self):
        d, _ = V.decide({"kind": "report_pointer",
                         "link_observed": "https://x.example/a"})
        self.assertEqual(d, "RESEARCH_ONLY")

    def test_clean_audit_becomes_negative(self):
        d, _ = V.decide({"kind": "report_pointer",
                         "link_observed": "https://x.example/a",
                         "zero_findings_declared": True})
        self.assertEqual(d, "IMPORT_AS_NEGATIVE")

    def test_nothing_observed_rejects(self):
        d, _ = V.decide({"kind": "report_pointer"})
        self.assertEqual(d, "REJECT")


class TestArtefacts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ledger = V.read_jsonl(V.DERIVED_VB / "candidate_ledger.jsonl")
        cls.records = V.read_jsonl(V.DERIVED_VB / "records.jsonl")
        cls.manifest = V.read_json(V.DERIVED_VB / "manifest.json")
        cls.split = V.read_json(V.SPLITS_VB / "split.json")
        cls.cands = {c["cid"]: c
                     for c in V.read_json(V.VBETA_DIR / "candidates.json")}
        solodit_path = V.VBETA_DIR / "solodit_candidates.json"
        if solodit_path.exists():
            for c in V.read_json(solodit_path):
                cls.cands[c["cid"]] = c

    def test_counts(self):
        self.assertEqual(len(self.ledger), 844)
        self.assertEqual(self.manifest["candidate_count"], 844)
        self.assertEqual(self.manifest["record_count"], len(self.records))
        self.assertEqual(len(self.records), 719)
        dec = {k: v for k, v in self.manifest["decisions"].items()}
        self.assertEqual(dec.get("IMPORT"), 60)
        self.assertEqual(dec.get("IMPORT_AS_NEGATIVE"), 5)
        self.assertEqual(dec.get("IMPORT_AS_UNVERIFIED"), 654)
        self.assertEqual(dec.get("RESEARCH_ONLY"), 62)
        self.assertEqual(dec.get("CORROBORATION_ONLY"), 63)

    def test_new_languages_present(self):
        langs = {r["language"] for r in self.ledger}
        for lang in ("circom", "noir", "leo", "cairo", "move", "go",
                     "typescript", "rust", "solidity"):
            self.assertIn(lang, langs, f"missing language {lang}")

    def test_no_level_above_l1(self):
        for r in self.ledger:
            self.assertIn(r["verification_level"], ("L0", "L1"))

    def test_l1_has_poc(self):
        for r in self.ledger:
            if r["verification_level"] == "L1":
                self.assertTrue(self.cands[r["candidate_id"]].get("poc_observed"))

    def test_splits_exact_and_isolated(self):
        ids = {r["finding_id"] for r in self.records}
        split_ids = (set(self.split["splits"]["train"])
                     | set(self.split["splits"]["validation"])
                     | set(self.split["splits"]["test"]))
        self.assertEqual(ids, split_ids)
        seen: dict[str, str] = {}
        for sname, members in self.split["splits"].items():
            for mid in members:
                sid = mid.split(":")[0]
                if sid in seen:
                    self.assertEqual(seen[sid], sname, f"source spans splits: {sid}")
                seen[sid] = sname

    def test_benchmark_rebuildable(self):
        recmap = {r["finding_id"]: r for r in self.records}
        for t in V.read_jsonl(V.BENCH_VB / "vbeta_U_language_routing.jsonl"):
            self.assertEqual(t["answer"], recmap[t["finding_id"]]["language"])
        for t in V.read_jsonl(V.BENCH_VB / "vbeta_V_source_tier_routing.jsonl"):
            self.assertEqual(t["answer"], str(recmap[t["finding_id"]]["source_tier"]))

    def test_present_sentinels_unchanged(self):
        import hashlib
        snap = V.read_json(V.VBETA_DIR / "present_snapshot.json")
        for rel, old in snap["sentinel_sha256"].items():
            cur = hashlib.sha256((V.ROOT / rel).read_bytes()).hexdigest()
            self.assertEqual(cur, old, f"PRESENT drifted: {rel}")

    def test_legacy_splits_pinned(self):
        split = V.read_json(V.SPLITS_VB / "split.json")
        expected = {"cantina-portfolio": "train",
                    "cyfrin-codehawks": "validation",
                    "immunefi-past-competitions": "test",
                    "movebit-sampled-audits": "train",
                    "neodyme-reports": "validation",
                    "openzeppelin-cairo": "test",
                    "ottersec-audits": "train",
                    "runtime-verification-publications": "validation",
                    "trailofbits-publications": "test",
                    "veridise-zk-archive": "train"}
        for sid, want in expected.items():
            self.assertEqual(split["assignment"].get(sid), want,
                             f"legacy split moved: {sid}")
        self.assertEqual(split["assignment"].get("shieldify-audits-portfolio"),
                         "validation")


class TestShieldify(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = [r for r in
                       V.read_jsonl(V.DERIVED_VB / "records.jsonl")
                       if r["source_id"] == "shieldify-audits-portfolio"]
        cls.ledger = [r for r in
                      V.read_jsonl(V.DERIVED_VB / "candidate_ledger.jsonl")
                      if r["source_id"] == "shieldify-audits-portfolio"]

    def test_finding_volume(self):
        self.assertEqual(len(self.ledger), 33)
        self.assertEqual(len(self.records), 27)

    def test_severity_verbatim(self):
        sevs = {r["severity_observed"] for r in self.records}
        self.assertTrue({"High", "Medium", "Low", "Informational"} <= sevs)

    def test_every_record_has_evidence(self):
        for r in self.records:
            ev = r.get("evidence")
            self.assertIsNotNone(ev, r["finding_id"])
            self.assertIn(ev["taxonomy_confidence"],
                          {"high", "medium", "low", "unknown"})
            self.assertTrue(ev["taxonomy"])
            self.assertTrue(ev["taxonomy_reason"])
            self.assertFalse(ev["verified_patch"])
            self.assertIn(ev["proof_type"],
                          {"published_poc_in_report", "none_observed"})

    def test_l1_matches_poc(self):
        l1 = sorted(r["finding_id"] for r in self.records
                    if r["verification_level"] == "L1")
        self.assertEqual(len(l1), 5)
        for r in self.records:
            if r["finding_id"] in l1:
                self.assertEqual(
                    r["evidence"]["proof_type"], "published_poc_in_report")

    def test_taxonomy_not_forced(self):
        unknowns = [r for r in self.records
                    if r["evidence"]["taxonomy"] == "unknown"]
        self.assertTrue(unknowns, "at least one row must refuse taxonomy")

    def test_no_code_redistributed(self):
        import json as _json
        blob = _json.dumps(self.records)
        self.assertNotIn("Team Response", blob)
        self.assertNotIn("winner_wallet PDA is created using", blob)


class TestSoloditHarvest(unittest.TestCase):
    SRC = "solodit-harvest"

    @classmethod
    def setUpClass(cls):
        cls.ledger = [r for r in
                      V.read_jsonl(V.DERIVED_VB / "candidate_ledger.jsonl")
                      if r["source_id"] == cls.SRC]
        cls.records = [r for r in
                       V.read_jsonl(V.DERIVED_VB / "records.jsonl")
                       if r["source_id"] == cls.SRC]
        cls.stats = V.read_json(V.REPORTS_VB / "solodit_harvest_stats.json")

    def test_volume_and_rejections(self):
        self.assertEqual(len(self.ledger), 733)
        self.assertEqual(self.stats["harvested"], 733)
        self.assertEqual(self.stats["rejected"], 1)
        self.assertEqual(self.stats["duplicates"][0]["duplicate_of"],
                         "cyfrin-codehawks:stablecoin-h-03")

    def test_0001_migrated_with_real_provenance(self):
        rows = [r for r in self.records
                if r["finding_id"].startswith(f"{self.SRC}:0001-")]
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual(r["decision"], "IMPORT")
        self.assertEqual(r["severity_observed"], "High Risk")
        self.assertEqual(r["status_observed"], "Fixed.")
        self.assertEqual(r["verification_level"], "L0")
        self.assertIn("Withdrawal Request Manipulation", r["title"])
        self.assertIn("withdrawal", r["description"].lower())
        self.assertIn("PearVault.sol", r["evidence"]["code_location"])
        self.assertIn("f681d7cc31ba76d521038f65e0e060849de55345",
                      r["evidence"]["code_location"])
        self.assertIn("solodit.cyfrin.io/issues/", r["description"])

    def test_no_operator_rows_remain(self):
        for r in V.read_jsonl(V.DERIVED_VB / "candidate_ledger.jsonl"):
            self.assertNotEqual(r.get("origin", "harvested"),
                                "user_contributed")

    def test_poc_rows_are_l1_with_proof(self):
        # 51 ledger L1 (incl. 2 quarantined whose kept rows carry the same
        # PoC); 49 admitted L1 records. No quoted PoC is lost: every
        # quarantined PoC row's kept counterpart has poc_observed=true.
        l1 = [r for r in self.records
              if r["verification_level"] == "L1"]
        self.assertEqual(len(l1), 49)
        for r in l1:
            self.assertEqual(r["evidence"]["proof_type"],
                             "published_poc_in_report")

    def test_severity_normalized_closed_and_raw_kept(self):
        for r in self.records:
            self.assertIn(r.get("severity_normalized"),
                          ("critical", "high", "medium", "low",
                           "informational", "unknown"),
                          r["finding_id"])
            # The observed string is always kept alongside; the derived
            # field never overwrites it.
            self.assertIn("severity_observed", r, r["finding_id"])

    def test_quarantine_never_admitted_twice(self):
        rec_ids = {r["finding_id"] for r in self.records}
        dups = V.read_jsonl(V.DERIVED_VB / "duplicates.jsonl")
        self.assertEqual(len(dups), 63)
        for d in dups:
            self.assertNotIn(d["candidate_id"], rec_ids)
            self.assertIn(d["duplicate_of"], rec_ids |
                          {r["candidate_id"] for r in
                           V.read_jsonl(V.DERIVED_VB / "candidate_ledger.jsonl")})
        quarantine = V.read_jsonl(V.SPLITS_VB / "quarantine.jsonl")
        self.assertEqual({r["candidate_id"] for r in quarantine},
                         {d["candidate_id"] for d in dups})

    def test_flows_into_benchmark_tasks(self):
        u = {t["finding_id"] for t in
             V.read_jsonl(V.BENCH_VB / "vbeta_U_language_routing.jsonl")
             if t["input"]["source_id"] == self.SRC}
        v = {t["finding_id"] for t in
             V.read_jsonl(V.BENCH_VB / "vbeta_V_source_tier_routing.jsonl")
             if t["input"]["source_id"] == self.SRC}
        rec_ids = {r["finding_id"] for r in self.records}
        self.assertTrue(v >= rec_ids)
        self.assertTrue(u <= rec_ids)
        self.assertTrue(u)  # known-language rows yield U tasks


if __name__ == "__main__":
    unittest.main(verbosity=2)
