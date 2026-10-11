"""Unit tests for the V3.2 execution-evidence promotion.

Run:  python -m unittest tests.test_v32_execution
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import v32_execution as X  # noqa: E402


class TestEvidenceKey(unittest.TestCase):
    def test_three_spellings_collapse(self):
        want = "2024-04/PikeFinance_exp"
        for ref in ("defihacklabs:src/test/2024-04/PikeFinance_exp",
                    "defihacklabs:2024-04/PikeFinance_exp.sol",
                    "2024-04/PikeFinance_exp.sol"):
            self.assertEqual(X.evidence_key(ref), want, ref)

    def test_past_mirror_and_backslash(self):
        self.assertEqual(
            X.evidence_key("defihacklabs:src\\test\\2020-06\\Bancor_exp"),
            "2020-06/Bancor_exp")

    def test_blank_is_safe(self):
        self.assertEqual(X.evidence_key(""), "")
        self.assertEqual(X.evidence_key(None), "")


class TestL5RequiresProfit(unittest.TestCase):
    def test_l5_without_profit_demoted_to_l4(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "reports" / "v3").mkdir(parents=True)
            (root / "reports" / "v3" / "experimental_proof.json").write_text(
                json.dumps({"runs": [{
                    "finding_id": "defihacklabs:2024-04/X_exp.sol",
                    "level_awarded": "L5",
                    "status": "violation_observed",
                    "profit_deltas": [],          # no profit evidence
                }]}), encoding="utf-8")
            ev = X.load_evidence(root)
        entry = ev["2024-04/X_exp"]
        self.assertEqual(entry["level"], "L4",
                         "L5 must be refused without attacker-side profit")
        self.assertEqual(entry["status"], "executed_no_profit_evidence")

    def test_l5_with_profit_kept(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "reports" / "v3").mkdir(parents=True)
            (root / "reports" / "v3" / "experimental_proof.json").write_text(
                json.dumps({"runs": [{
                    "finding_id": "defihacklabs:2024-04/X_exp.sol",
                    "level_awarded": "L5",
                    "status": "violation_observed",
                    "profit_deltas": [
                        {"label_before": "attacker weth",
                         "label_after": "attacker weth",
                         "before": 1, "after": 500,
                         "profit": 499, "attacker_side": True}],
                }]}), encoding="utf-8")
            ev = X.load_evidence(root)
        self.assertEqual(ev["2024-04/X_exp"]["level"], "L5")
        self.assertEqual(ev["2024-04/X_exp"]["profit_evidence"]["max_profit"], 499)

    def test_non_attacker_profit_is_not_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "reports" / "v3").mkdir(parents=True)
            (root / "reports" / "v3" / "experimental_proof.json").write_text(
                json.dumps({"runs": [{
                    "finding_id": "defihacklabs:2024-04/X_exp.sol",
                    "level_awarded": "L5",
                    "status": "violation_observed",
                    "profit_deltas": [
                        {"label_before": "victim weth", "label_after": "victim weth",
                         "before": 500, "after": 1, "profit": -499,
                         "attacker_side": False}],
                }]}), encoding="utf-8")
            ev = X.load_evidence(root)
        self.assertEqual(ev["2024-04/X_exp"]["level"], "L4")


class TestPromote(unittest.TestCase):
    def _cand(self, cid="defihacklabs:src/test/2024-04/X_exp"):
        return {"candidate_id": cid, "source_id": "defihacklabs",
                "verification_level": "L1", "verification_status": "UNVERIFIED",
                "verification_evidence": "published PoC (not executed)",
                "_signals": {"poc": 3}}

    def test_unexecuted_untouched(self):
        c = self._cand()
        before = dict(c)
        n = X.promote([c], {})
        self.assertEqual(n, 0)
        self.assertEqual(c, before, "an unexecuted record must not change")

    def test_promotion_sets_fields(self):
        c = self._cand()
        ev = {"2024-04/X_exp": {"level": "L3", "status": "compiled",
                                "basis": "forge build rc=0"}}
        self.assertEqual(X.promote([c], ev), 1)
        self.assertEqual(c["verification_level"], "L3")
        self.assertEqual(c["verification_status"], "COMPILES")
        self.assertEqual(c["experiment"]["level_awarded"], "L3")

    def test_l5_status_and_profit_block(self):
        c = self._cand()
        ev = {"2024-04/X_exp": {
            "level": "L5", "status": "violation_observed",
            "basis": "attacker profit > 0", "profit_evidence": {"max_profit": 42}}}
        X.promote([c], ev)
        self.assertEqual(c["verification_status"], "VIOLATION_REPRODUCED")
        self.assertEqual(c["experiment"]["profit_evidence"]["max_profit"], 42)

    def test_promotion_is_idempotent(self):
        c = self._cand()
        ev = {"2024-04/X_exp": {"level": "L3", "status": "compiled",
                                "basis": "forge build rc=0"}}
        X.promote([c], ev)
        snap = json.dumps(c, sort_keys=True)
        X.promote([c], ev)
        self.assertEqual(json.dumps(c, sort_keys=True), snap)

    def test_l6_never_derived_from_sweep(self):
        c = self._cand()
        ev = {"2024-04/X_exp": {"level": "L6", "status": "x", "basis": "y"}}
        X.promote([c], ev)
        self.assertIn(c["verification_status"], X.LEVEL_TO_STATUS.values())


class TestVerifiedFact(unittest.TestCase):
    def test_unknown_without_evidence(self):
        self.assertEqual(X.verified_fact(None), "unknown")
        self.assertEqual(X.verified_fact({}), "unknown")

    def test_l3_states_no_execution(self):
        fact = X.verified_fact({"level": "L3", "clone_head": "a" * 40})
        self.assertIn("compiles", fact)
        self.assertIn("nothing was executed", fact)

    def test_l4_states_violation_not_reproduced(self):
        fact = X.verified_fact({"level": "L4", "clone_head": "a" * 40})
        self.assertIn("NOT reproduced", fact)

    def test_l5_states_profit(self):
        fact = X.verified_fact({
            "level": "L5", "clone_head": "a" * 40,
            "profit_evidence": {"max_profit": 479.39,
                                "label_before": "attacker", "label_after": "attacker"}})
        self.assertIn("479.39", fact)


class TestArtefactPaths(unittest.TestCase):
    def test_absolute_local_path_becomes_relative(self):
        root = Path("C:/repo")
        rel = X._rel_artifact(root, "C:/repo/experiments_v3/pikefinance")
        self.assertEqual(rel, "experiments_v3/pikefinance")

    def test_unresolvable_path_is_dropped(self):
        self.assertIsNone(X._rel_artifact(
            Path("C:/repo"), "C:/elsewhere/experiments_v3/x"))


class TestShippedLayer(unittest.TestCase):
    """The committed layer must satisfy the promotion rules end to end."""

    def test_records_agree_with_arifacts(self):
        recs = [json.loads(line) for line in
                (ROOT / "derived_v3" / "records.jsonl")
                .open(encoding="utf-8") if line.strip()]
        executed = [r for r in recs
                    if r.get("verification_level") in ("L3", "L4", "L5", "L6")]
        self.assertTrue(executed,
                        "the V3.2 overlay should have promoted records")
        for r in executed:
            exp = r.get("experiment")
            self.assertIsNotNone(exp, r["finding_id"])
            if r["verification_level"] in ("L4", "L5", "L6"):
                d = exp.get("artifact_dir")
                self.assertTrue(d and (ROOT / d).is_dir(),
                                f"{r['finding_id']}: artefact dir {d}")
            if r["verification_level"] == "L5":
                self.assertTrue(exp.get("profit_evidence"),
                                f"{r['finding_id']}: L5 without profit")
            self.assertNotEqual(r.get("verified_fact"), "unknown",
                                f"{r['finding_id']}: level without an "
                                "observed-fact sentence")

    def test_no_promotion_without_artefact_key(self):
        recs = [json.loads(line) for line in
                (ROOT / "derived_v3" / "records.jsonl")
                .open(encoding="utf-8") if line.strip()]
        bad = [r["finding_id"] for r in recs
               if r.get("verification_level") in ("L3", "L4", "L5", "L6")
               and "experiment" not in r]
        self.assertEqual(bad, [])

    def test_l6_never_present(self):
        recs = [json.loads(line) for line in
                (ROOT / "derived_v3" / "records.jsonl")
                .open(encoding="utf-8") if line.strip()]
        self.assertEqual([r["finding_id"] for r in recs
                          if r.get("verification_level") == "L6"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)