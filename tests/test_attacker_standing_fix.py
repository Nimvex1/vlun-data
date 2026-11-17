#!/usr/bin/env python3
"""Attacker standing must not be laundered out of VLUN's own checker output.

Three failures are pinned here, all observed on 2024-04-noya/H-01 before the fix:

  A. self-ingestion. `security_reasoning.attacker_limitations` carries sentences
     written by this pipeline's access-control checker, not by the audit report.
     `attacker_model` scanned them as prose and quoted one back as
     `evidence_type: reported_claim` — the dataset citing itself as an external
     source.
  B. negation blindness. The quoted sentence says an unprivileged attacker
     CANNOT reach the function. The matcher saw the word "unprivileged" and
     labelled the standing `unprivileged`, contradicting `attacker_constraints`
     in the same record.
  C. a missing standing. A flaw that corrupts valuation/accounting during normal
     or privileged protocol operation is neither an unprivileged attacker nor a
     malicious privileged one. Both noya records are that case.

The noya rows are read from the read-only canonical layer and transformed in
memory; nothing here writes to jsonl/ or derived/.
Run:  python -m unittest tests.test_attacker_standing_fix -v
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import build_derived as bd  # noqa: E402
import schema_terms as st  # noqa: E402
from vlun import ATTACKER_KINDS  # noqa: E402

PROTOCOL_FLAW = "protocol_accounting_or_config_flaw"

# The checker's own voice, as committed in jsonl/findings.jsonl. These are
# pipeline output, never a source claim.
GENERATED_LIMITATIONS = (
    "`NoyaValueOracle.updatePriceRoute` is external but gated by `onlyMaintainer`: "
    "an unprivileged attacker cannot reach it directly, so a finding that assumes "
    "free access to this function is not valid as stated",
    "`Vault.withdraw` is public but gated by `onlyOwner`: an unprivileged attacker "
    "cannot reach it directly, so a finding that assumes free access to this "
    "function is not valid as stated",
    "`Vault._sweep` is internal, so it is only reachable through an internal call "
    "path; a direct external call by an attacker is impossible",
    "`Vault._sweep` is private, so it is only reachable through an internal call "
    "path; a direct external call by an attacker is impossible",
)

NEGATED_UNPRIVILEGED = (
    "an unprivileged attacker cannot reach it directly",
    "an unprivileged attacker can't reach it directly",
    "any user can call this is not valid as stated",
    "the entry point is not reachable by an unprivileged caller",
    "an arbitrary caller is unable to reach the setter",
    "anyone can call drain() is not valid as stated",
    "callers are restricted to the maintainer, so any user cannot invoke it",
)

# A real source claim: the negation guard must not swallow these.
POSITIVE_UNPRIVILEGED = (
    "any user can call drain()",
    "anyone can withdraw the whole balance",
    "an unprivileged attacker can call the setter directly",
)


def _row(limitations=(), capabilities=(), title="a review of the module", ctx=None):
    return {
        "source": {"repository": "repo"},
        "finding": {"id": "repo/H-01", "title": title, "summary": "", "root_cause": ""},
        "security_reasoning": {
            "attacker_limitations": list(limitations),
            "attacker_capabilities": list(capabilities),
        },
        "code_context": list(ctx or []),
    }


def _identity(row):
    return bd.attacker_model(row, bd.expanded_context(row), row["finding"])["attacker_identity"]


def _snippet_row(modifier="onlyMaintainer", function="updatePriceRoute"):
    """A record whose only code evidence is the committed report snippet."""
    return _row(
        title="Value of asset token can be incorrect when the ETH/USD oracle is needed",
        ctx=[{
            "file": "code-423n4/repo/contracts/NoyaValueOracle.sol",
            "contract": "NoyaValueOracle", "function": function,
            "snippet": f"    function {function}(address asset, address base) external {modifier} {{\n"
                       "        priceRoutes[asset][base] = asset;\n    }",
            "commit_sha": "c" * 40, "line_range_verified": True,
        }],
    )


def _noya_rows():
    want = {"2024-04-noya/H-01", "2024-04-noya/H-02"}
    out = {}
    with open(ROOT / "jsonl" / "findings.jsonl", encoding="utf-8") as fh:
        for line in fh:
            row = json.loads(line)
            fid = (row.get("finding") or {}).get("id")
            if fid in want:
                out[fid] = row
    return out


def _states_unreachable(constraint_text: str) -> bool:
    low = constraint_text.lower()
    gate = "gated by" in low or "onlyreachable" in low.replace(" ", "") \
        or "only reachable through an internal" in low
    denied = any(m in low for m in ("cannot reach", "can't reach", "is impossible",
                                    "not valid as stated", "not reachable"))
    return gate and denied


class TestNegationWindows(unittest.TestCase):
    def test_a_negated_mention_is_never_an_unprivileged_attribution(self):
        for sentence in NEGATED_UNPRIVILEGED:
            with self.subTest(sentence=sentence):
                kind, _ = bd.reported_attacker_kind([sentence])
                self.assertNotEqual(kind, "unprivileged")

    def test_a_negated_limitation_never_labels_the_standing_unprivileged(self):
        for sentence in NEGATED_UNPRIVILEGED:
            with self.subTest(sentence=sentence):
                identity = _identity(_row(limitations=[sentence]))
                self.assertNotEqual(identity["value"], "unprivileged")

    def test_a_negated_capability_never_labels_the_standing_unprivileged(self):
        for sentence in NEGATED_UNPRIVILEGED:
            with self.subTest(sentence=sentence):
                identity = _identity(_row(capabilities=[sentence]))
                self.assertNotEqual(identity["value"], "unprivileged")

    def test_a_genuine_unprivileged_claim_still_classifies(self):
        for sentence in POSITIVE_UNPRIVILEGED:
            with self.subTest(sentence=sentence):
                kind, attributed = bd.reported_attacker_kind([sentence])
                self.assertEqual(kind, "unprivileged")
                self.assertEqual(attributed, sentence)


class TestNoSelfIngestion(unittest.TestCase):
    def test_checker_prose_is_never_a_reported_claim(self):
        for sentence in GENERATED_LIMITATIONS:
            with self.subTest(sentence=sentence[:60]):
                identity = _identity(_row(limitations=[sentence]))
                self.assertNotEqual(identity["evidence_type"], "reported_claim")
                self.assertNotEqual(identity["basis"], "reported_claim")
                self.assertNotEqual(identity.get("attributed_sentence"), sentence)

    def test_checker_prose_copied_into_another_field_is_still_not_a_source(self):
        for sentence in GENERATED_LIMITATIONS:
            with self.subTest(sentence=sentence[:60]):
                identity = _identity(_row(capabilities=[sentence]))
                self.assertNotEqual(identity["basis"], "reported_claim")

    def test_report_authored_limitations_stay_reported_claims(self):
        text = ("deposit/mint/withdraw/redeem functions have a onlyWhiteListed modifier "
                "that means they can only be called by someone who is within the "
                "enabledAccounts")
        am = bd.attacker_model(_row(limitations=[text]), [], {"title": "", "summary": "",
                                                             "root_cause": ""})
        tagged = [c for c in am["attacker_constraints"] if c["value"] == text]
        self.assertEqual(len(tagged), 1)
        self.assertEqual(tagged[0]["evidence_type"], "reported_claim")


class TestModifierConstraintsAreDerived(unittest.TestCase):
    def test_a_snippet_only_record_still_gets_a_mechanical_gate(self):
        row = _snippet_row()
        am = bd.attacker_model(row, *_args(row))
        gates = am["access_control_observations"]
        self.assertTrue(gates, "the committed snippet carries onlyMaintainer; "
                              "the gate must be observed without a local checkout")
        self.assertEqual(gates[0]["verdict"], "privileged_callers_only")
        self.assertEqual(gates[0]["evidence_type"], "derived_fact")
        self.assertIn("maintainer", am["trusted_roles"])

    def test_modifier_constraints_carry_derived_fact_and_a_rule_pointer(self):
        row = _snippet_row()
        row["security_reasoning"]["attacker_limitations"] = [GENERATED_LIMITATIONS[0]]
        am = bd.attacker_model(row, *_args(row))
        tagged = am["attacker_constraints"]
        self.assertEqual(len(tagged), 1)
        self.assertEqual(tagged[0]["evidence_type"], "derived_fact")
        self.assertTrue(tagged[0]["source_refs"], "a derived constraint must point at its rule")
        self.assertNotEqual(tagged[0]["evidence_type"], "reported_claim")

    def test_required_permissions_name_the_observed_modifier(self):
        row = _snippet_row()
        am = bd.attacker_model(row, *_args(row))
        perms = am["required_permissions"]
        self.assertTrue(any(p["role"] == "maintainer" and p["evidence_type"] == "derived_fact"
                            for p in perms), perms)


class TestNoyaStanding(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = _noya_rows()
        cls.records = {rid: bd.build_record(row, {}) for rid, row in cls.rows.items()}

    def test_both_records_are_present_in_the_canonical_layer(self):
        self.assertEqual(set(self.records), {"2024-04-noya/H-01", "2024-04-noya/H-02"})

    def test_standing_is_in_the_closed_vocabulary(self):
        for rid, rec in self.records.items():
            with self.subTest(record=rid):
                identity = rec["attacker_model"]["attacker_identity"]
                self.assertIn(identity["value"], ATTACKER_KINDS)
                self.assertIn(identity["evidence_type"], st.EVIDENCE_TYPES)

    def test_constraints_and_identity_never_contradict(self):
        for rid, rec in self.records.items():
            with self.subTest(record=rid):
                am = rec["attacker_model"]
                identity = am["attacker_identity"]
                for constraint in am["attacker_constraints"]:
                    text = constraint["value"] if isinstance(constraint, dict) else constraint
                    if _states_unreachable(text):
                        self.assertNotEqual(
                            identity["value"], "unprivileged",
                            f"{rid}: constraint says an unprivileged caller cannot reach the "
                            f"function, identity says unprivileged")

    def test_no_identity_is_attributed_to_pipeline_prose(self):
        for rid, rec in self.records.items():
            with self.subTest(record=rid):
                identity = rec["attacker_model"]["attacker_identity"]
                attributed = identity.get("attributed_sentence")
                if attributed:
                    self.assertNotIn(attributed, GENERATED_LIMITATIONS)
                    self.assertFalse(bd.is_pipeline_generated_prose(attributed))

    def test_h01_is_a_protocol_accounting_flaw_not_an_unprivileged_attacker(self):
        identity = self.records["2024-04-noya/H-01"]["attacker_model"]["attacker_identity"]
        self.assertEqual(identity["value"], PROTOCOL_FLAW)
        self.assertEqual(identity["basis"], "derived_fact")
        self.assertEqual(identity["source_refs"], ["rule:build_derived.py:attacker_model"])

    def test_h02_is_a_protocol_accounting_flaw_not_unknown(self):
        identity = self.records["2024-04-noya/H-02"]["attacker_model"]["attacker_identity"]
        self.assertEqual(identity["value"], PROTOCOL_FLAW)
        self.assertEqual(identity["basis"], "derived_fact")

    def test_the_gated_setter_is_observed_in_both_records(self):
        for rid, rec in self.records.items():
            with self.subTest(record=rid):
                am = rec["attacker_model"]
                self.assertTrue(am["access_control_observations"], rid)
                self.assertTrue(am["trusted_roles"], rid)


class TestCapabilityCheckerVoice(unittest.TestCase):
    """The checker also writes capability lines; those are not source claims."""

    SHAPES = (
        "can call `AccountingManager.TVL` directly (public, no access-control modifier)",
        "can call `Vault.withdraw` directly (external, no access-control modifier)",
        "can call `Vault.withdraw` directly (external, `onlyOwner`)",
        "can call `Vault.withdraw` directly (public, `onlyOwner`, `nonReentrant`)",
        "can call `Vault.withdraw` directly (public, `onlyOwner`)",
    )

    def test_every_capability_shape_is_tagged_derived(self):
        for text in self.SHAPES:
            with self.subTest(text=text[:50]):
                self.assertTrue(bd.is_pipeline_generated_prose(text))
                am = bd.attacker_model(_row(capabilities=[text]), [],
                                       {"title": "", "summary": "", "root_cause": ""})
                tagged = [c for c in am["attacker_capabilities"] if c["value"] == text]
                self.assertEqual(len(tagged), 1)
                self.assertEqual(tagged[0]["evidence_type"], "derived_fact")
                self.assertTrue(tagged[0]["source_refs"])

    def test_a_report_authored_capability_still_classifies(self):
        # 2024-01-decent/M-02: genuine report prose that also says "directly (".
        text = ("any user can conduct the pre-bridge swap operation using uniswap by himself, "
                "prepare the right calldata and call the function directly (any calldata)")
        self.assertFalse(bd.is_pipeline_generated_prose(text))
        am = bd.attacker_model(_row(capabilities=[text]), [],
                               {"title": "", "summary": "", "root_cause": ""})
        self.assertEqual([c["evidence_type"] for c in am["attacker_capabilities"]],
                         ["reported_claim"])
        self.assertEqual(am["attacker_identity"]["value"], "unprivileged")


class TestAccountingRulePrecision(unittest.TestCase):
    def test_subject_and_defect_must_share_a_sentence(self):
        row = _snippet_row()
        row["finding"]["title"] = "Share price is read by the vault."
        row["security_reasoning"]["impact"] = {
            "integrity": "The migration ran incorrectly last week."}
        identity = _identity(row)
        self.assertNotEqual(identity["value"], PROTOCOL_FLAW)
        self.assertEqual(identity["value"], "privileged")

    def test_a_same_sentence_defect_does_classify(self):
        row = _snippet_row()
        row["finding"]["title"] = "The share price is incorrect after the migration."
        self.assertEqual(_identity(row)["value"], PROTOCOL_FLAW)

    def test_a_malicious_privileged_claim_wins_over_the_flaw_label(self):
        for actor in ("a malicious manager", "malicious managers", "a rogue owner",
                      "the compromised admin", "a privileged attacker"):
            with self.subTest(actor=actor):
                row = _snippet_row()
                row["finding"]["title"] = (
                    f"The share price is incorrect and {actor} can drain the vault")
                identity = _identity(row)
                self.assertNotEqual(identity["value"], PROTOCOL_FLAW)
                self.assertEqual(identity["value"], "privileged")


class TestCorpusAuthorship(unittest.TestCase):
    """The authorship rule holds across the whole canonical layer, not just noya."""

    @classmethod
    def setUpClass(cls):
        cls.rows = []
        for family in ("findings.jsonl", "negative_findings.jsonl"):
            with open(ROOT / "jsonl" / family, encoding="utf-8") as fh:
                cls.rows += [json.loads(line) for line in fh if line.strip()]

    def test_no_identity_anywhere_is_attributed_to_pipeline_prose(self):
        bad, constraints = [], 0
        for row in self.rows:
            am = bd.attacker_model(row, bd.expanded_context(row), row["finding"])
            identity = am["attacker_identity"]
            attributed = identity.get("attributed_sentence")
            if attributed and bd.is_pipeline_generated_prose(attributed):
                bad.append(row["finding"]["id"])
            for c in am["attacker_constraints"]:
                constraints += 1
                want = ("derived_fact" if bd.is_pipeline_generated_prose(c["value"])
                        else "reported_claim")
                self.assertEqual(c["evidence_type"], want, row["finding"]["id"])
        self.assertEqual(bad, [])
        self.assertGreater(constraints, 300)

    def test_a_negated_limitation_never_yields_an_unprivileged_standing(self):
        bad = []
        for row in self.rows:
            limits = (row.get("security_reasoning") or {}).get("attacker_limitations") or []
            if not any(bd.is_pipeline_generated_prose(s) and "cannot reach it directly" in s
                       for s in limits):
                continue
            identity = _identity(row)["value"]
            if identity == "unprivileged":
                bad.append(row["finding"]["id"])
        self.assertEqual(bad, [])


class TestUnmappedRoleModifier(unittest.TestCase):
    """An `onlyX` the library has never heard of still gates callers.

    2024-01-decent/submission-746 is gated by `onlyExecutor`, which is not in
    MODIFIER_LIBRARY. Empty required_roles made the gate summary answer
    `no_check_observed`, so the record was labelled `unprivileged` while its own
    constraint said an unprivileged attacker cannot reach the function.
    """

    def test_an_unmapped_only_modifier_is_still_a_role_gate(self):
        import solidity_facts as sf
        src = ("    function sgReceive(uint16 _srcChainId, bytes calldata _payload) "
               "external onlyExecutor {\n        _doReceive(_payload);\n    }")
        facts = sf.analyse(src, "sgReceive")
        target = facts["target_function"]
        self.assertEqual(target["modifiers"], ["onlyExecutor"])
        self.assertEqual(target["required_roles"], ["role_member"])
        gate = sf.access_control_summary(facts)
        self.assertEqual(gate["verdict"], "privileged_callers_only")
        self.assertEqual(gate["evidence_type"], "derived_fact")

    def test_a_non_role_modifier_is_not_promoted_to_a_role(self):
        import solidity_facts as sf
        src = ("    function deposit(uint256 amount) external nonReentrant {\n"
               "        total += amount;\n    }")
        facts = sf.analyse(src, "deposit")
        self.assertEqual(facts["target_function"]["required_roles"], [])
        self.assertEqual(sf.access_control_summary(facts)["verdict"],
                         "unprivileged_but_reentrancy_guarded")

    def test_the_decent_row_no_longer_contradicts_its_own_constraint(self):
        row = None
        for family in ("findings.jsonl", "negative_findings.jsonl"):
            with open(ROOT / "jsonl" / family, encoding="utf-8") as fh:
                for line in fh:
                    candidate = json.loads(line)
                    if (candidate.get("finding") or {}).get("id") == "2024-01-decent/submission-746":
                        row = candidate
        self.assertIsNotNone(row, "the corpus row this regression pins must exist")
        identity = _identity(row)
        self.assertNotEqual(identity["value"], "unprivileged")
        self.assertIn("role_member", bd.attacker_model(
            row, bd.expanded_context(row), row["finding"])["trusted_roles"])


class TestStandingVocabulary(unittest.TestCase):
    def test_the_vocabulary_covers_protocol_configuration_flaws(self):
        self.assertIn(PROTOCOL_FLAW, ATTACKER_KINDS)
        self.assertIn(PROTOCOL_FLAW, st.ATTACKER_KINDS)
        self.assertEqual(tuple(st.ATTACKER_KINDS), tuple(ATTACKER_KINDS))

    def test_the_vocabulary_checker_accepts_members_and_rejects_typos(self):
        for kind in ATTACKER_KINDS:
            self.assertEqual(st.check_attacker_kind(kind, "test"), kind)
        with self.assertRaises(st.TerminologyError):
            st.check_attacker_kind("protocol_accounting_flaw", "test")

    def test_every_emitted_vocabulary_list_is_the_canonical_one(self):
        identity = _identity(_row())
        self.assertEqual(identity["vocabulary"], list(ATTACKER_KINDS))


def _args(row):
    return bd.expanded_context(row), row["finding"]


if __name__ == "__main__":
    unittest.main()