#!/usr/bin/env python3
"""Tests for the canonical terminology module (scripts/schema_terms.py).

Includes intentionally-broken inputs: every validator must reject them.
Run:  python -m unittest discover -s tests  (or pytest)
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import schema_terms as T  # noqa: E402


class TestVocabularyShape(unittest.TestCase):
    def test_decisions_closed(self):
        self.assertEqual(tuple(T.DECISIONS),
                         ("IMPORT", "IMPORT_AS_UNVERIFIED",
                          "IMPORT_AS_NEGATIVE", "CORROBORATION_ONLY",
                          "REJECT", "RESEARCH_ONLY"))

    def test_levels_l0_to_l6(self):
        self.assertEqual(tuple(T.VERIFICATION_LEVELS),
                         ("L0", "L1", "L2", "L3", "L4", "L5", "L6"))

    def test_evidence_states(self):
        self.assertEqual(len(T.EVIDENCE_TYPES), 7)
        for s in ("reported_claim", "observed_fact", "derived_fact",
                  "experimentally_verified", "externally_attributed",
                  "unverified", "unknown"):
            self.assertIn(s, T.EVIDENCE_TYPES)

    def test_patch_fields_are_roles_not_values(self):
        self.assertEqual(tuple(T.PATCH_FIELDS),
                         ("recommended_fix", "team_reported_status",
                          "verified_patch"))

    def test_count_domains_cover_units(self):
        for unit in ("candidate", "admitted_record", "derived_record",
                     "preview_row", "benchmark_task", "quarantine_row"):
            self.assertIn(unit, T.COUNT_DOMAINS)

    def test_layers_and_splits(self):
        self.assertIn("vbeta", T.LAYERS)
        self.assertEqual(tuple(T.SPLITS), ("train", "validation", "test"))


class TestValidatorsRejectBroken(unittest.TestCase):
    def test_bad_level_rejected(self):
        for bad in ("L7", "L-1", "reproduced", "verified", "", "l1"):
            with self.assertRaises(T.TerminologyError, msg=bad):
                T.check_evidence_level(bad, "test")

    def test_good_levels_accepted(self):
        for lvl in ("L0", "L1", "L6"):
            self.assertEqual(T.check_evidence_level(lvl, "test"), lvl)

    def test_bad_decision_rejected(self):
        for bad in ("MAYBE", "import", "VERIFIED", ""):
            with self.assertRaises(T.TerminologyError, msg=bad):
                T.check_decision(bad, "test")

    def test_bad_verification_state_rejected(self):
        with self.assertRaises(T.TerminologyError):
            T.check_verification_state("proven", "test")

    def test_deprecated_terms_rejected(self):
        for bad in ("verified source confirms",
                    "the bug was reproduced yesterday",
                    "Fixed (verified) by team",
                    "ground truth label"):
            with self.assertRaises(T.TerminologyError, msg=bad):
                T.check_no_deprecated(bad, "test")

    def test_clean_prose_passes(self):
        T.check_no_deprecated("published PoC observed in report", "test")
        T.check_no_deprecated("team_reported_status Fixed", "test")


class TestPatchCoherence(unittest.TestCase):
    def test_verified_patch_without_level_fails(self):
        with self.assertRaises(T.TerminologyError):
            T.check_patch_coherence(
                {"verification_level": "L1", "verified_patch": True}, "test")

    def test_verified_patch_with_l6_passes(self):
        T.check_patch_coherence(
            {"verification_level": "L6", "verified_patch": True}, "test")

    def test_team_fixed_is_not_proof(self):
        # verified_patch absent/False with team Fixed: fine, no promotion.
        T.check_patch_coherence(
            {"verification_level": "L0", "status_observed": "Fixed",
             "evidence": {"verified_patch": False}}, "test")

    def test_evidence_block_promotion_fails(self):
        with self.assertRaises(T.TerminologyError):
            T.check_patch_coherence(
                {"verification_level": "L0",
                 "evidence": {"verified_patch": True}}, "test")


class TestNoDriftedCopies(unittest.TestCase):
    def test_vbeta_copies_match_canonical(self):
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent
                               / "Vbeta" / "scripts"))
        import vlun_vbeta as V
        self.assertEqual(tuple(V.DECISIONS), tuple(T.DECISIONS))
        self.assertEqual(tuple(V.VERIFICATION_LEVELS),
                         tuple(T.VERIFICATION_LEVELS))
        self.assertEqual(tuple(V.NEGATIVE_CLASSES), tuple(T.NEGATIVE_CLASSES))

    def test_ladder_defined_once(self):
        # The L0-L6 ladder lives in poc_classification and is re-exported;
        # schema_terms fails at import on any drift (asserted here too).
        from poc_classification import POC_LEVELS
        self.assertEqual(set(POC_LEVELS), set(T.VERIFICATION_LEVELS))
        self.assertEqual(len(T.VERIFICATION_LEVELS), 7)


if __name__ == "__main__":
    unittest.main(verbosity=2)
