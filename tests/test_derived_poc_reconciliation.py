#!/usr/bin/env python3
"""Bug #4 regression: the derived PoC view must be reconciled, not mirrored.

Pins the five properties that were wrong after Prompt 5:
  1. the terminal assertion is the differential assertion, not the baseline;
  2. setup-only `updatePriceRoute` is a precondition, not the attacker step;
  3. the vulnerable read is localised to ChainlinkOracleConnector.getValue;
  4. final_state is populated from the terminal assertion;
  5. PoC reproducibility is reconciled with the committed experiment verdict,
     and "not attempted" is tri-state unknown, never False.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import build_derived as bd  # noqa: E402
import solidity_facts as sf  # noqa: E402

H01 = "2024-04-noya/H-01"
DERIVED = ROOT / "derived" / "records.jsonl"
JSONL = ROOT / "jsonl"


def _read_jsonl(path: Path) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _h01_row() -> dict:
    for row in _read_jsonl(JSONL / "findings.jsonl"):
        if (row.get("finding") or {}).get("id") == H01:
            return row
    raise AssertionError("H-01 source row missing")


def _h01_record() -> dict:
    for rec in _read_jsonl(DERIVED):
        if rec.get("id") == H01:
            return rec
    raise AssertionError("H-01 derived record missing")


class TestPoCExtractor(unittest.TestCase):
    def test_terminal_assertion_is_the_differential_one(self):
        pa = sf.analyse_poc(_h01_row()["poc"]["code"])
        self.assertEqual(pa["assertion_count"], 3)
        self.assertEqual(pa["baseline_assertion"]["statement"],
                         "assertEq(valueDirect, 99998495);")
        self.assertEqual(pa["terminal_assertion"]["statement"],
                         "assertEq(valueIndirect / valueDirect, 9981679525);")
        self.assertIn("assertEq(valueIndirect, 998152930103816659);",
                      [a["statement"] for a in pa["terminal_assertions"]])

    def test_setup_holds_prank_and_route_not_the_attacker_step(self):
        setup = sf.analyse_poc(_h01_row()["poc"]["code"])["setup_preconditions"]
        self.assertIn("vm.startPrank(owner);", setup)
        self.assertIn("noyaOracle.updatePriceRoute(address(USDC), address(840), assets);", setup)
        self.assertFalse(any("assertEq" in s for s in setup))

    def test_trigger_is_localised_to_connector_getvalue(self):
        loc = sf.analyse_poc(_h01_row()["poc"]["code"])["localised_trigger"]
        self.assertEqual(loc["contract"], "ChainlinkOracleConnector")
        self.assertEqual(loc["function"], "getValue")
        self.assertEqual(loc["evidence_type"], "derived_fact")


class TestReconciledLayer(unittest.TestCase):
    def test_h01_poc_reproducible_and_observed_impact_are_reconciled(self):
        poc = _h01_record()["poc"]
        self.assertEqual(poc["observed_impact"],
                         "assertEq(valueIndirect / valueDirect, 9981679525);")
        self.assertIs(poc["reproducible"], True)
        self.assertEqual(poc["attempt_status"], "executed")
        self.assertEqual(poc["evidence_type"], "experimentally_verified")
        self.assertIn("forge_status=Success", poc["reproducibility_note"])

    def test_h01_state_transition_is_populated_and_localised(self):
        st = _h01_record()["security_state_transition"]
        self.assertEqual(st["final_state"]["value"],
                         "assertEq(valueIndirect / valueDirect, 9981679525);")
        self.assertEqual(st["initial_state"]["value"],
                         "assertEq(valueDirect, 99998495);")
        self.assertEqual(st["final_state"]["evidence_type"], "experimentally_verified")
        self.assertIn("noyaOracle.updatePriceRoute(address(USDC), address(840), assets);",
                      st["setup_preconditions"])
        step = st["transactions"][0]
        self.assertEqual((step["contract"], step["function"]),
                         ("ChainlinkOracleConnector", "getValue"))
        self.assertNotIn("updatePriceRoute", step["action"])

    def test_execution_status_is_tri_state(self):
        self.assertIsNone(bd.poc_execution(None)["reproducible"])
        self.assertEqual(bd.poc_execution(None)["attempt_status"], "not_attempted")
        self.assertIs(bd.poc_execution({"verdict": "reproduced"})["reproducible"], True)
        self.assertIs(bd.poc_execution({"verdict": "not_reproduced"})["reproducible"], False)

    def test_no_reproduced_record_keeps_a_stale_poc(self):
        for rec in _read_jsonl(DERIVED):
            if (rec.get("verification") or {}).get("verdict") != "reproduced":
                continue
            poc = rec.get("poc") or {}
            self.assertIs(poc.get("reproducible"), True, rec["id"])
            self.assertEqual(poc.get("attempt_status"), "executed", rec["id"])
            pa = poc.get("poc_analysis") or {}
            terminal = (pa.get("terminal_assertion") or {}).get("statement")
            if terminal:
                self.assertEqual(poc.get("observed_impact"), terminal, rec["id"])

    def test_no_record_has_an_unknown_final_state_with_a_terminal_assertion(self):
        for rec in _read_jsonl(DERIVED):
            pa = ((rec.get("poc") or {}).get("poc_analysis") or {})
            if not pa.get("terminal_assertion"):
                continue
            st = rec.get("security_state_transition") or {}
            self.assertTrue((st.get("final_state") or {}).get("value"), rec["id"])
            self.assertNotEqual((st.get("final_state") or {}).get("evidence_type"),
                                "unknown", rec["id"])


if __name__ == "__main__":
    unittest.main()
