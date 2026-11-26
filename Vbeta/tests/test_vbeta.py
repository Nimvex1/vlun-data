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
        for extra in ("solodit_candidates.json", "web3bugs_candidates.json",
                        "scabench_candidates.json",
                        "lisabench_candidates.json"):
            extra_path = V.VBETA_DIR / extra
            if extra_path.exists():
                for c in V.read_json(extra_path):
                    cls.cands[c["cid"]] = c

    def test_counts(self):
        # Only FULLY_TRAINABLE rows survive the purge (>=50 chars inline code
        # AND >=100 chars technical prose). All 80 come from solodit-harvest.
        self.assertEqual(len(self.ledger), 80)
        self.assertEqual(self.manifest["candidate_count"], 80)
        self.assertEqual(self.manifest["record_count"], len(self.records))
        self.assertEqual(len(self.records), 80)
        self.assertEqual(self.manifest["source_count"], 15)
        # candidate_decisions is explicitly the retained CANDIDATE population.
        dec = dict(self.manifest["candidate_decisions"])
        self.assertEqual(sum(dec.values()), 80)
        self.assertEqual(dec, {"IMPORT_AS_UNVERIFIED": 80})
        self.assertEqual(self.manifest["candidate_by_source"],
                         {"solodit-harvest": 80})
        # admitted_* distributions sum to the admitted records.
        for key in ("admitted_by_language", "admitted_by_ecosystem"):
            self.assertEqual(sum(self.manifest[key].values()), 80, key)
        self.assertEqual(
            sum(self.manifest["candidate_verification_levels"].values()), 80)
        self.assertEqual(self.manifest["quarantine_rows"], 31996)  # 26960 -> 31996: Option A purge of jsonl_vbeta/findings.jsonl stub rows

    def test_trainable_languages_present(self):
        langs = {r["language"] for r in self.ledger}
        self.assertEqual(langs, {"go", "rust", "solidity"})

    def test_every_retained_row_is_fully_trainable(self):
        import json as _json
        for r in self.records:
            code = max((len(str(c.get("snippet") or ""))
                        for c in (r.get("code_context") or [])
                        if isinstance(c, dict)), default=0)
            self.assertGreaterEqual(code, 50, r["finding_id"])
            self.assertGreaterEqual(len(r.get("description") or ""), 100,
                                    r["finding_id"])
        qpath = V.VBETA_DIR / "derived_vbeta" / "quarantine.jsonl"
        qrows = [_json.loads(line) for line in
                 qpath.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertTrue(qrows)
        self.assertTrue(all(r["reason"] == "UNHYDRATABLE_DEAD_POINTER"
                            for r in qrows))

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
        snap = V.read_json(V.VBETA_DIR / "present_snapshot.json")
        for rel, old in snap["sentinel_sha256"].items():
            cur = V.text_file_sha256(V.ROOT / rel)
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
        self.assertEqual(split["assignment"].get("solodit-harvest"), "train")
        self.assertEqual(split["assignment"].get("web3bugs"), "test")
        self.assertEqual(split["assignment"].get("scabench"), "validation")
        self.assertEqual(split["assignment"].get("scabench"), "validation")


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
        # No shieldify row carries both inline code and >=100 chars of prose.
        self.assertEqual(len(self.ledger), 0)
        self.assertEqual(len(self.records), 0)

    def test_severity_verbatim(self):
        sevs = {r["severity_observed"] for r in self.records}
        self.assertEqual(sevs, set())

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
        self.assertEqual(len(l1), 0)
        for r in self.records:
            if r["finding_id"] in l1:
                self.assertEqual(
                    r["evidence"]["proof_type"], "published_poc_in_report")

    def test_taxonomy_not_forced(self):
        unknowns = [r for r in self.records
                    if r["evidence"]["taxonomy"] == "unknown"]
        self.assertEqual(unknowns, [], "no shieldify rows survive the purge")

    def test_no_code_redistributed(self):
        import json as _json
        blob = _json.dumps(self.records)
        self.assertNotIn("Team Response", blob)
        self.assertNotIn("winner_wallet PDA is created using", blob)


class TestWeb3Bugs(unittest.TestCase):
    SRC = "web3bugs"

    @classmethod
    def setUpClass(cls):
        cls.ledger = [r for r in
                      V.read_jsonl(V.DERIVED_VB / "candidate_ledger.jsonl")
                      if r["source_id"] == cls.SRC]
        cls.records = [r for r in
                       V.read_jsonl(V.DERIVED_VB / "records.jsonl")
                       if r["source_id"] == cls.SRC]

    def test_volume_and_decisions(self):
        # No web3bugs row carries both inline code and >=100 chars of prose.
        self.assertEqual(len(self.ledger), 0)
        self.assertEqual(len(self.records), 0)
        decs = {r["decision"] for r in self.records}
        self.assertEqual(decs, set())

    def test_labels_are_not_severities(self):
        # Oracle-difficulty labels must never leak into severity fields.
        for r in self.records:
            self.assertEqual(r["severity_observed"], "High")
            self.assertIn("oracle-difficulty", r["description"])

    def test_links_are_code4rena_reports(self):
        for r in self.ledger:
            loc = r.get("source_location") or ""
            self.assertTrue(loc.startswith("https://code4rena.com/reports/"),
                            r["candidate_id"])


class TestScaBench(unittest.TestCase):
    SRC = "scabench"

    @classmethod
    def setUpClass(cls):
        cls.ledger = [r for r in
                      V.read_jsonl(V.DERIVED_VB / "candidate_ledger.jsonl")
                      if r["source_id"] == cls.SRC]
        cls.records = [r for r in
                       V.read_jsonl(V.DERIVED_VB / "records.jsonl")
                       if r["source_id"] == cls.SRC]

    def test_volume_and_decisions(self):
        # No scabench row carries both inline code and >=100 chars of prose.
        self.assertEqual(len(self.ledger), 0)
        self.assertEqual(len(self.records), 0)
        decs = {r["decision"] for r in self.records}
        self.assertEqual(decs, set())

    def test_commit_pinned_links(self):
        for r in self.ledger:
            loc = r.get("source_location") or ""
            self.assertTrue(loc.startswith("https://github.com/"),
                            r["candidate_id"])

    def test_language_honestly_unknown(self):
        langs = {r["language"] for r in self.records}
        self.assertEqual(langs, set())

    def test_adjudication_mined_as_attribution(self):
        named = [r for r in self.records
                 if "submitter unknown via" not in
                 r["evidence"]["attribution"]]
        self.assertEqual(len(named), 0)


class TestLisabench(unittest.TestCase):
    SRC = "lisabench"

    @classmethod
    def setUpClass(cls):
        cls.ledger = [r for r in
                      V.read_jsonl(V.DERIVED_VB / "candidate_ledger.jsonl")
                      if r["source_id"] == cls.SRC]
        cls.records = [r for r in
                       V.read_jsonl(V.DERIVED_VB / "records.jsonl")
                       if r["source_id"] == cls.SRC]

    def test_volume_and_decisions(self):
        # No lisabench row carries both inline code and >=100 chars of prose.
        self.assertEqual(len(self.ledger), 0)
        self.assertEqual(len(self.records), 0)
        decs = {r["decision"] for r in self.records}
        self.assertEqual(decs, set())

    def test_severity_verbatim_including_gas(self):
        sevs = {r["severity_observed"] for r in self.records}
        self.assertEqual(sevs, set())

    def test_code_content_never_copied(self):
        # Contract bodies carry these markers; prose titles do not.
        import json as _json
        blob = _json.dumps(self.records)
        for marker in ("SPDX-License-Identifier", "pragma solidity",
                       "vm.prank", "mapping(address"):
            self.assertNotIn(marker, blob)

    def test_links_resolve_to_issues_or_contests(self):
        bad = [r["candidate_id"] for r in self.ledger
               if not (r.get("source_location") or "").startswith(
                   "https://")]
        self.assertEqual(bad, [])


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
        # 80 solodit rows survive the FULLY_TRAINABLE purge; the harvest stats
        # remain the history of the original 733-row harvest.
        self.assertEqual(len(self.ledger), 80)
        self.assertEqual(len(self.records), 80)
        self.assertEqual(self.stats["harvested"], 733)
        self.assertEqual(self.stats["rejected"], 1)
        self.assertEqual(self.stats["duplicates"][0]["duplicate_of"],
                         "cyfrin-codehawks:stablecoin-h-03")

    def test_dead_pointer_0001_was_quarantined(self):
        # The 0001 PearVault row had a DEAD code pointer, so it was removed
        # from the trainable tables rather than left as a STUB.
        import json as _json
        rows = [r for r in self.records
                if r["finding_id"].startswith(f"{self.SRC}:0001-")]
        self.assertEqual(rows, [])
        qpath = V.VBETA_DIR / "derived_vbeta" / "quarantine.jsonl"
        qrows = [_json.loads(line) for line in
                 qpath.read_text(encoding="utf-8").splitlines() if line.strip()]
        dead = [r for r in qrows
                if str(r.get("id", "")).startswith(f"{self.SRC}:0001-")]
        self.assertTrue(dead)
        self.assertEqual(dead[0]["reason"], "UNHYDRATABLE_DEAD_POINTER")

    def test_no_operator_rows_remain(self):
        for r in V.read_jsonl(V.DERIVED_VB / "candidate_ledger.jsonl"):
            self.assertNotEqual(r.get("origin", "harvested"),
                                "user_contributed")

    def test_poc_rows_are_l1_with_proof(self):
        # 12 L1 rows survive the FULLY_TRAINABLE purge (all solodit-harvest).
        l1 = [r for r in self.records
              if r["verification_level"] == "L1"]
        self.assertEqual(len(l1), 12)
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
        self.assertEqual(len(dups), 0, "non-trainable duplicate links were purged")
        for d in dups:
            self.assertNotIn(d["candidate_id"], rec_ids)
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
