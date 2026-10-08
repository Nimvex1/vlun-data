#!/usr/bin/env python3
"""Logic unit tests: severity parser, scorer core, subset admission rules.

Unlike the manifest tests, these pin BEHAVIOUR with hand-computed fixtures:
a violating record must be rejected, a known mapping must hold, and the
scorer's arithmetic must match a hand calculation.
Run:  python -m unittest discover -s tests
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "Vbeta" / "scripts"))
from score_benchmark import score_tasks  # noqa: E402
from vlun_vbeta import normalize_severity  # noqa: E402


RAW_SEVERITIES = {
    "**Critical Risk**": "critical",
    "**High Risk**": "high",
    "**Impact**: High, Denial of service and high gas costs to us": "high",
    "**Impact**: High, malicious attacker can set L2 custom addre": "high",
    "**Impact**: Medium, distributors are generally trusted actor": "medium",
    "**Impact**: Medium, temporary DOS of funds": "medium",
    "**Impact:** High": "high",
    "**Impact:** Low": "low",
    "**Impact:** Medium": "medium",
    "**Impact:** Medium, fee will be a little higher/lower": "medium",
    "**Impact:** Medium, gateway will still has its old address": "medium",
    "**Medium Risk**": "medium",
    "Critical": "critical",
    "Critical Risk": "critical",
    "High": "high",
    "High Risk": "high",
    "Informational": "informational",
    "Insight": "unknown",
    "Low": "low",
    "Medium": "medium",
    "Medium Risk": "medium",
    "Minor": "unknown",
    None: "unknown",
}


class TestSeverityParser(unittest.TestCase):
    def test_all_observed_strings_map_or_unknown(self):
        # Every raw severity string ever seen in Vbeta candidates: closed
        # vocab or explicit unknown — no silent pass-through, no KeyError.
        for raw, want in RAW_SEVERITIES.items():
            got, reason = normalize_severity(raw)
            self.assertEqual(got, want, f"raw={raw!r} reason={reason}")
            self.assertTrue(reason, f"empty reason for {raw!r}")

    def test_vocab_closed(self):
        from vlun_vbeta import SEVERITY_NORMALIZED_VOCAB
        self.assertEqual(tuple(SEVERITY_NORMALIZED_VOCAB),
                         ("critical", "high", "medium", "low",
                          "informational", "unknown"))


FIX_TASKS = {
    # task_id: (family, gold, scorable)
    "A::t1": ("A", "vulnerable", True),
    "A::t2": ("A", "no_confirmed_vulnerability", True),
    "A::t3": ("A", "vulnerable", True),
    "A::t4": ("A", "vulnerable", False),  # unscorable: never counted
    "K::t1": ("K", "solidity", True),
    "K::t2": ("K", "rust", True),
}
FIX_SPLITS = {"A::t1": "train", "A::t2": "train", "A::t3": "test",
              "A::t4": "test", "K::t1": "train", "K::t2": "test"}
# Hand computation: predictions t1=vulnerable(ok), t2=rust(no),
# t3 missing, K::t1=solidity(ok), K::t2=rust(ok).
FIX_PREDS = {"A::t1": "Vulnerable", "A::t2": "rust",
             "K::t1": "SOLIDITY", "K::t2": "rust"}


class TestScorerCore(unittest.TestCase):
    def test_hand_computed_accuracy(self):
        rep = score_tasks(FIX_TASKS, FIX_PREDS, FIX_SPLITS)
        a = rep["families"]["A"]
        # A: scorable 3 (t4 excluded), predicted 2, correct 1.
        self.assertEqual((a["scorable"], a["predicted"], a["correct"]),
                         (3, 2, 1))
        self.assertAlmostEqual(a["accuracy"], 0.5)
        self.assertAlmostEqual(a["accuracy_scorable"], 1 / 3)
        k = rep["families"]["K"]
        self.assertEqual((k["scorable"], k["predicted"], k["correct"]),
                         (2, 2, 2))
        m = rep["micro"]
        # Micro: scorable 5, predicted 4, correct 3.
        self.assertEqual((m["scorable"], m["predicted"], m["correct"]),
                         (5, 4, 3))
        self.assertAlmostEqual(m["accuracy"], 0.75)
        self.assertAlmostEqual(m["accuracy_scorable"], 0.6)

    def test_split_accounting(self):
        rep = score_tasks(FIX_TASKS, FIX_PREDS, FIX_SPLITS)
        tr = rep["families"]["A"]["splits"]["train"]
        self.assertEqual((tr["scorable"], tr["predicted"], tr["correct"]),
                         (2, 2, 1))
        te = rep["families"]["A"]["splits"]["test"]
        self.assertEqual((te["scorable"], te["predicted"], te["correct"]),
                         (1, 0, 0))
        self.assertIsNone(te["accuracy"])

    def test_normalization_case_insensitive(self):
        rep = score_tasks({"t": ("F", "invalid", True)},
                          {"t": "  INVALID "}, {"t": "train"})
        self.assertEqual(rep["micro"]["correct"], 1)


class TestSubsetAdmission(unittest.TestCase):
    def test_finding_rule(self):
        from build_subsets import admits_finding
        good = {
            "code_context": [{"source_url": "https://github.com/o/r/blob/"
                                            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                            "/f.sol"}],
            "code_context_expanded": [{"retrieved_locally": True}],
        }
        self.assertTrue(admits_finding(good))
        # No immutable citation -> rejected.
        bad_url = {"code_context": [{"source_url": "https://x/y"}],
                   "code_context_expanded": [{"retrieved_locally": True}]}
        self.assertFalse(admits_finding(bad_url))
        # Nothing retrieved locally -> rejected.
        bad_ret = {"code_context": good["code_context"],
                   "code_context_expanded": []}
        self.assertFalse(admits_finding(bad_ret))
        # Empty record -> rejected, never admitted by default.
        self.assertFalse(admits_finding({}))

    def test_exploit_patch_negative_rules(self):
        from build_subsets import (admits_exploit, admits_negative,
                                   admits_patch)
        self.assertTrue(admits_exploit({"poc_level": "L5"}))
        self.assertTrue(admits_exploit({"poc_level": "L6"}))
        self.assertFalse(admits_exploit({"poc_level": "L4"}))
        self.assertFalse(admits_exploit({}))
        self.assertTrue(admits_patch({"fix_effectiveness": "effective"}))
        self.assertFalse(admits_patch({"fix_effectiveness": "partial"}))
        for ok in ("experimentally_verified", "attributed",
                   "corroborated_duplicate"):
            self.assertTrue(admits_negative({"negative_class": ok}))
        self.assertFalse(admits_negative({"negative_class": "unverified"}))
        self.assertFalse(admits_negative({}))


class TestNormalizationLogic(unittest.TestCase):
    def test_severity_exact_and_scales(self):
        from normalize_v3_lib import normalize_severity
        self.assertEqual(
            normalize_severity("High", "pashov-audits")[0], "High")
        self.assertEqual(
            normalize_severity("Major", "abdk-audits")[0], "High")
        self.assertEqual(
            normalize_severity("whatever", "x")[0], "unknown")
        self.assertEqual(normalize_severity("", "x")[0], "unknown")
        # Conservative by design: near-miss strings do NOT map (changing
        # this would rewrite thousands of derived rows).
        self.assertEqual(
            normalize_severity("High Risk", "pashov-audits")[0], "unknown")

    def test_taxonomy_signal_based(self):
        from normalize_v3_lib import map_taxonomy
        labels, conf, _, _ = map_taxonomy(
            None, "Reentrancy attack via callback",
            "external call before state change")
        self.assertEqual(labels, ["Reentrancy"])
        labels, conf, _, _ = map_taxonomy(None, "mystery", "nothing here")
        self.assertEqual(labels, ["Unknown"])

    def test_language_eco_resolution(self):
        from normalize_v3_lib import resolve_lang_eco
        self.assertEqual(
            resolve_lang_eco(["src/Foo.sol"], "pragma solidity",
                             "unknown", "unknown", "unknown")[:2],
            ("solidity", "evm"))
        # Existing values are sticky: never overwritten by weaker signals.
        self.assertEqual(
            resolve_lang_eco([], "nothing", "solidity", "evm",
                             "observed_fact")[:2],
            ("solidity", "evm"))

    def test_v1_taxonomy_classify(self):
        from taxonomy import classify
        out = classify({"vulnerability_classes":
                        ["Access Control/missing authorization"]})
        self.assertEqual(out["category"], "Access Control")
        self.assertEqual(classify({})["category"], "Unknown")
        self.assertEqual(classify(
            {"vulnerability_classes": ["no/such-class"]})["category"],
            "Unknown")


if __name__ == "__main__":
    unittest.main(verbosity=2)
