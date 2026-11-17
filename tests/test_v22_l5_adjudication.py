#!/usr/bin/env python3
"""The 35 V2.2 L5 claims are adjudicated from artefact bytes, and the derived
view obeys it.

Before the 2026-11-01 remediation the adjudication was written from prose
reasoning; it was not derivable from the committed run artefacts and was
inverted in places (the two 1c/1a cases and the declared differential harness
came out on the wrong side). The file is now a deterministic function of
`experiments_v2_2/<id>/result.json` and `stdout.txt`, built by
`scripts/build_v22_l5_adjudication.py` under the rule published in its header:

    SUPPORTED (stays L5) iff some cited test satisfies rule 1a (a test the
    artefact DECLARES failing, in its `expectation.declared.fail` list, with a
    non-empty `[FAIL: <reason>]` line), rule 1b (a met `stdout_contains`
    differential harness whose named lines are in stdout), or rule 1c (a
    passing test whose `Logs:` block prints `key = <numeric value>`);
    WEAK (L4, provisional) when the test is present and passed but the
    artefact declares only `all_pass` and records no claim-specific
    observation; UNSUPPORTED when the stdout is empty / the test is absent
    (L1) or the record's own text is tagged `(NEGATIVE CONTROL)` /
    "mitigated in practice" (L4).

The computed partition is 5 SUPPORTED / 27 WEAK / 3 UNSUPPORTED. The verdicts
are committed in reports/v2_2/l5_adjudication.json and applied by
scripts/build_derived_v22.py to `experiment_view` only; `jsonl_ml/` keeps its
original claim in `level_before`. These tests read both, so a quiet edit to a
verdict, a missing record or a level that drifts from its verdict fails here.

The expected ids and verdicts below are written out rather than derived from
the adjudication file, and TestAdjudicationIsDerived re-derives the verdicts
from fixture artefacts and from the committed run bytes themselves, so a
future edit cannot hand-assign L5 again.

Run:  python -m unittest tests.test_v22_l5_adjudication
"""
from __future__ import annotations

import collections
import copy
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import build_derived_v22 as bd  # noqa: E402
import build_v22_l5_adjudication as bld  # noqa: E402

SUPPORTED = {
    "solidity:zentory-contracts-audit/H2",
    "solidity:zentory-mode-a/H-1",
    "solidity:zentory-mode-a/H-2",
    "solidity:zentory-mode-a/H-3",
    "vyper:GHSA-6j9c-gvcw-74fj",
}
SUPPORTED_CLAUSE = {
    "solidity:zentory-contracts-audit/H2": "Rule 1a",
    "vyper:GHSA-6j9c-gvcw-74fj": "Rule 1b",
    "solidity:zentory-mode-a/H-1": "Rule 1c",
    "solidity:zentory-mode-a/H-2": "Rule 1c",
    "solidity:zentory-mode-a/H-3": "Rule 1c",
}
WEAK = {
    "solidity:kerf-report/H-1",
    "solidity:kerf-report/H-2",
    "solidity:kerf-report/H-3",
    "solidity:kerf-report/M-1",
    "solidity:quantillon-report/H-1",
    "solidity:zentory-contracts-audit/H3",
    "solidity:zentory-mode-a/M-1",
    "solidity:zentory-mode-a/M-2",
    "solidity:zentory-self-audit/C-1",
    "solidity:zentory-self-audit/H-01",
    "solidity:zentory-self-audit/H-02",
    "solidity:zentory-self-audit/H-03",
    "solidity:zentory-self-audit/H-04",
    "solidity:zentory-self-audit/H-05",
    "solidity:zentory-self-audit/H-06",
    "solidity:zentory-self-audit/H-06b",
    "solidity:zentory-self-audit/H-07",
    "solidity:zentory-self-audit/M-01",
    "solidity:zentory-self-audit/M-02",
    "solidity:zentory-self-audit/M-03",
    "solidity:zentory-self-audit/M-04",
    "solidity:zentory-self-audit/M-05",
    "solidity:zentory-self-audit/M-06",
    "solidity:zentory-self-audit/M-07",
    "solidity:zentory-self-audit/M-08",
    "solidity:zentory-self-audit/S-3",
    "solidity:zentory-self-audit/SC-4",
}
UNSUPPORTED = {
    "solidity:zentory-self-audit/M-09": "L1",
    "solidity:zentory-self-audit/SC-5": "L4",
    "solidity:zentory-self-audit/O-01": "L4",
}
ALL_L5 = SUPPORTED | WEAK | set(UNSUPPORTED)
COUNTS = {"L5_records": 35, "SUPPORTED": 5, "WEAK": 27, "UNSUPPORTED": 3}

WEAK_CORE_REASON = (
    "the committed artefact declares only `all_pass` and records no "
    "claim-specific observation, and no test body is published, so the "
    "violation is not demonstrable from the artefact")


class AdjudicationBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.findings, cls.registry = bd.load_layer()
        cls.by_id = {f["id"]: f for f in cls.findings}
        cls.adjudications = bd.load_adjudication()

    def view(self, rid: str) -> dict:
        entry = self.adjudications[rid]
        return bd.experiment_view(self.by_id[rid], entry)

    def mutated(self, mutate) -> Path:
        """Write a copy of the committed adjudication through `mutate`."""
        doc = json.loads(bd.ADJUDICATION.read_text(encoding="utf-8"))
        doc = copy.deepcopy(doc)
        mutate(doc)
        tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False,
                                          encoding="utf-8")
        with tmp:
            json.dump(doc, tmp, ensure_ascii=False, indent=2, sort_keys=True)
        self.addCleanup(Path(tmp.name).unlink)
        return Path(tmp.name)


class TestCoverage(AdjudicationBase):
    def test_the_adjudication_covers_the_35_l5_claims_exactly(self):
        source_l5 = {f["id"] for f in self.findings
                     if (f.get("experiment") or {}).get("level") == "L5"}
        self.assertEqual(len(source_l5), 35,
                         "the source layer no longer claims exactly 35 L5 runs")
        self.assertEqual(set(self.adjudications), source_l5)
        self.assertEqual(set(self.adjudications), ALL_L5)
        # the record-level integrity check (ids, experiments, observed tests)
        bd.check_adjudication(self.findings, self.adjudications)

    def test_no_duplicate_record_ids(self):
        doc = json.loads(bd.ADJUDICATION.read_text(encoding="utf-8"))
        ids = [e["record_id"] for e in doc["adjudications"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(doc["expected_records"], len(ids))

        def duplicate(d):
            d["adjudications"].append(copy.deepcopy(d["adjudications"][0]))
            d["expected_records"] = len(d["adjudications"])
            d["counts"]["L5_records"] = len(d["adjudications"])

        with self.assertRaises(bd.AdjudicationError) as caught:
            bd.load_adjudication(self.mutated(duplicate))
        self.assertIn("duplicate record_id", str(caught.exception))

    def test_header_declares_the_rule_counts_and_generator(self):
        doc = json.loads(bd.ADJUDICATION.read_text(encoding="utf-8"))
        self.assertEqual(doc["record_type"], "l5_adjudication")
        self.assertEqual(doc["counts"], COUNTS)
        self.assertEqual(doc["generated_by"],
                         "scripts/build_v22_l5_adjudication.py")
        rule = doc["rule"]
        for key in ("supported_1a", "supported_1b", "supported_1c",
                    "weak", "unsupported"):
            self.assertIn(key, rule)
        review = doc["analyst_review"]
        self.assertTrue(review["performed_by"])
        self.assertIn("verdict_definitions", review)
        # the method must no longer claim a prose-only review
        self.assertIn("build_v22_l5_adjudication.py", review["method"])
        self.assertIn("artefact bytes", review["method"])
        self.assertNotIn("manual", review["performed_by"].lower())

    def test_each_evidence_is_a_verbatim_quote_from_a_committed_artefact(self):
        pat = re.compile(r"experiments_v2_2/[A-Za-z0-9._-]+/"
                         r"(?:result|stdout|stderr)\.(?:json|txt)")
        missing = []
        for rid, entry in self.adjudications.items():
            refs = pat.findall(entry["evidence"])
            if not refs:
                missing.append(f"{rid}: no artefact reference in evidence")
                continue
            for ref in refs:
                if not (ROOT / ref).is_file():
                    missing.append(f"{rid}: {ref} does not exist")
            head, _, rest = entry["evidence"].partition(": ")
            cited = ROOT / refs[0]
            if head.endswith("stdout.txt") and rest == "is 0 bytes":
                if cited.stat().st_size != 0:
                    missing.append(f"{rid}: claims 0 bytes, file is not empty")
            elif rest and rest not in cited.read_text(encoding="utf-8"):
                missing.append(f"{rid}: evidence quote is not verbatim "
                               f"artefact bytes")
        self.assertEqual(missing, [])


class TestUnsupported(AdjudicationBase):
    def test_three_unsupported_claims_demote_to_the_expected_levels(self):
        unsupported = {rid for rid, e in self.adjudications.items()
                       if e["verdict"] == "UNSUPPORTED"}
        self.assertEqual(unsupported, set(UNSUPPORTED))
        self.assertEqual(len(unsupported), 3)
        for rid, level in UNSUPPORTED.items():
            entry = self.adjudications[rid]
            self.assertEqual(entry["level_before"], "L5")
            self.assertEqual(entry["level_after"], level)
            self.assertFalse(entry["provisional"])
            self.assertTrue(entry["status_after"])
            self.assertTrue(entry["reason"])
            view = self.view(rid)
            self.assertEqual(view["level"], level)
            self.assertEqual(view["level_before"], "L5")
            self.assertEqual(view["adjudication_verdict"], "UNSUPPORTED")
            self.assertTrue(view["demoted_from_L5"])
            self.assertTrue(view["demotion_reason"])
            self.assertFalse(view["verification_provisional"])
            self.assertNotIn("l5_candidate", view)
            # a demoted record keeps its evidence fields but no longer reads
            # as fully verified L5
            self.assertNotEqual(view["evidence_type"], "experimentally_verified")
            self.assertTrue(view["artefacts"])

    def test_the_three_unsupported_cases_are_the_rule_3_ones(self):
        m09 = self.adjudications["solidity:zentory-self-audit/M-09"]
        self.assertEqual(m09["level_after"], "L1")
        self.assertIn("insufficient_evidence", m09["reason"])
        self.assertIn("0 bytes", m09["evidence"])
        sc5 = self.adjudications["solidity:zentory-self-audit/SC-5"]
        self.assertEqual(sc5["level_after"], "L4")
        self.assertIn("negative control", sc5["reason"])
        self.assertEqual(self.adjudications[
            "solidity:zentory-self-audit/O-01"]["level_after"], "L4")
        o01 = self.adjudications["solidity:zentory-self-audit/O-01"]
        self.assertIn("mitigated in practice", o01["reason"])


class TestWeak(AdjudicationBase):
    def test_twenty_seven_weak_claims_are_l4_and_provisional(self):
        weak = {rid for rid, e in self.adjudications.items()
                if e["verdict"] == "WEAK"}
        self.assertEqual(weak, WEAK)
        self.assertEqual(len(weak), 27)
        for rid in weak:
            entry = self.adjudications[rid]
            self.assertEqual(entry["level_before"], "L5")
            self.assertEqual(entry["level_after"], "L4")
            self.assertTrue(entry["provisional"])
            self.assertIn(WEAK_CORE_REASON, entry["reason"])
            view = self.view(rid)
            self.assertEqual(view["level"], "L4")
            self.assertEqual(view["level_before"], "L5")
            self.assertTrue(view["verification_provisional"])
            self.assertTrue(view["l5_candidate"])
            self.assertIn(WEAK_CORE_REASON, view["provisional_reason"])
            self.assertEqual(view["adjudication_verdict"], "WEAK")
            self.assertFalse(view.get("demoted_from_L5", False))


class TestSupported(AdjudicationBase):
    def test_five_supported_claims_stay_l5(self):
        supported = {rid for rid, e in self.adjudications.items()
                     if e["verdict"] == "SUPPORTED"}
        self.assertEqual(supported, SUPPORTED)
        self.assertEqual(len(supported), 5)
        for rid in supported:
            entry = self.adjudications[rid]
            self.assertEqual(entry["level_before"], "L5")
            self.assertEqual(entry["level_after"], "L5")
            self.assertFalse(entry["provisional"])
            view = self.view(rid)
            self.assertEqual(view["level"], "L5")
            self.assertEqual(view["level_before"], "L5")
            self.assertFalse(view["verification_provisional"])
            self.assertFalse(view.get("l5_candidate", False))
            self.assertFalse(view.get("demoted_from_L5", False))

    def test_each_supported_claim_cites_the_rule_clause_that_decides_it(self):
        for rid, clause in SUPPORTED_CLAUSE.items():
            entry = self.adjudications[rid]
            self.assertIn(clause, entry["reason"], rid)
        h2 = self.adjudications["solidity:zentory-contracts-audit/H2"]
        self.assertIn("[FAIL: ", h2["evidence"])
        vyper = self.adjudications["vyper:GHSA-6j9c-gvcw-74fj"]
        self.assertIn("CHECK pass", vyper["evidence"])
        for rid in ("solidity:zentory-mode-a/H-1", "solidity:zentory-mode-a/H-2",
                    "solidity:zentory-mode-a/H-3"):
            self.assertRegex(self.adjudications[rid]["evidence"], r"= \d+")


class TestRejection(AdjudicationBase):
    def test_an_unknown_record_id_is_rejected(self):
        adj = dict(self.adjudications)
        bogus = copy.deepcopy(self.adjudications[sorted(SUPPORTED)[0]])
        bogus["record_id"] = "solidity:no-such-report/X-9"
        adj[bogus["record_id"]] = bogus
        with self.assertRaises(bd.AdjudicationError):
            bd.check_adjudication(self.findings, adj)

    def test_a_missing_record_id_is_rejected(self):
        adj = dict(self.adjudications)
        adj.pop(sorted(WEAK)[0])
        with self.assertRaises(bd.AdjudicationError):
            bd.check_adjudication(self.findings, adj)

    def test_a_hand_flipped_supported_verdict_fails_the_derivation_gate(self):
        """kerf's artefact declares only all_pass and its passing tests print
        no Logs block, so flipping one of its WEAK records to SUPPORTED is
        refused by the SUPPORTED-is-derived gate even though the file shape
        stays valid."""
        doc = json.loads(bd.ADJUDICATION.read_text(encoding="utf-8"))
        e = next(x for x in doc["adjudications"]
                 if x["record_id"] == "solidity:kerf-report/H-1")
        self.assertEqual(e["verdict"], "WEAK")
        e["verdict"] = "SUPPORTED"
        e["level_after"] = "L5"
        e["provisional"] = False
        e["status_after"] = "experimentally_verified"
        derived = self._artefact_supported_ids(doc)
        self.assertNotIn("solidity:kerf-report/H-1", derived,
                         "kerf-auditpoc has no decisive artefact line: a "
                         "hand-assigned SUPPORTED must fail the gate")

    @staticmethod
    def _artefact_supported_ids(doc):
        out = set()
        for e in doc["adjudications"]:
            for eid in e["experiment_ids"]:
                art = ROOT / "experiments_v2_2" / eid
                res = json.loads((art / "result.json").read_text(
                    encoding="utf-8"))
                txt = (art / "stdout.txt").read_text(encoding="utf-8")
                decl = (res.get("expectation") or {}).get("declared") or {}
                met = (res.get("expectation") or {}).get("met")
                has_fail = bool(re.search(r"^\[FAIL: .+\]", txt, re.M)) and \
                    bool(decl.get("fail"))
                has_diff = met is True and isinstance(
                    decl.get("stdout_contains"), list) and \
                    bool(decl.get("stdout_contains")) and \
                    all(s in txt for s in decl["stdout_contains"])
                has_num = any(
                    re.fullmatch(r"-?\d+(\.\d+)?([eE][-+]?\d+)?",
                                 ln.split("=", 1)[1].strip())
                    for ln in txt.splitlines()
                    if "=" in ln and ln[:1] in (" ", "\t")
                    and "CHECK" not in ln and "OBS" not in ln)
                if has_fail or has_diff or has_num:
                    out.add(e["record_id"])
        return out

    def test_malformed_adjudications_are_rejected(self):
        def drop_reason(doc):
            del doc["adjudications"][0]["reason"]

        def bad_verdict(doc):
            doc["adjudications"][0]["verdict"] = "MAYBE"

        def weak_at_l5(doc):
            e = next(x for x in doc["adjudications"] if x["verdict"] == "WEAK")
            e["level_after"] = "L5"

        def supported_provisional(doc):
            e = next(x for x in doc["adjudications"]
                     if x["verdict"] == "SUPPORTED")
            e["provisional"] = True

        def unsupported_provisional(doc):
            e = next(x for x in doc["adjudications"]
                     if x["verdict"] == "UNSUPPORTED")
            e["provisional"] = True

        def wrong_level_before(doc):
            doc["adjudications"][0]["level_before"] = "L4"

        def counts_disagree(doc):
            doc["counts"]["WEAK"] = 10

        def expected_records_disagree(doc):
            doc["expected_records"] = 34

        def missing_evidence(doc):
            doc["adjudications"][0]["evidence"] = ""

        for mutate in (drop_reason, bad_verdict, weak_at_l5,
                       supported_provisional, unsupported_provisional,
                       wrong_level_before, counts_disagree,
                       expected_records_disagree, missing_evidence):
            with self.subTest(mutation=mutate.__name__):
                with self.assertRaises(bd.AdjudicationError):
                    bd.load_adjudication(self.mutated(mutate))


class TestBuilderOutputsMatchManifest(AdjudicationBase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.rows = [bd.build_record(f, cls.registry, cls.adjudications)
                    for f in cls.findings]
        cls.manifest = bd.build_manifest(cls.rows, [])

    def test_manifest_levels_are_the_applied_levels(self):
        levels = collections.Counter(r["experiment_view"]["level"] or "none"
                                     for r in self.rows)
        self.assertEqual(self.manifest["experiment_levels"], dict(levels))
        self.assertEqual(self.manifest["experiment_levels"],
                         {"L1": 1, "L3": 1, "L4": 29, "L5": 5, "L6": 1,
                          "none": 100})

    def test_manifest_adjudication_counters_are_5_27_3(self):
        self.assertEqual(self.manifest["experiment_levels_verified_l5"], 5)
        self.assertEqual(self.manifest["experiment_levels_provisional"], 27)
        self.assertEqual(self.manifest["experiment_levels_demoted"], 3)
        self.assertEqual(
            self.manifest["experiment_levels_verified_l5"]
            + self.manifest["experiment_levels_provisional"]
            + self.manifest["experiment_levels_demoted"], 35)

    def test_every_adjudicated_record_carries_its_verdict_and_level(self):
        checked = 0
        for row in self.rows:
            entry = self.adjudications.get(row["id"])
            if entry is None:
                continue
            checked += 1
            view = row["experiment_view"]
            self.assertEqual(view["level"], entry["level_after"], row["id"])
            self.assertEqual(view["level_before"], "L5", row["id"])
            self.assertEqual(view["adjudication_verdict"], entry["verdict"],
                             row["id"])
            self.assertEqual(view["status_after"], entry["status_after"],
                             row["id"])
            self.assertEqual(view["adjudication_source"],
                             bd.ADJUDICATION_SOURCE, row["id"])
        self.assertEqual(checked, 35)

    def test_unadjudicated_records_keep_their_source_level(self):
        wrong = []
        for row in self.rows:
            if row["id"] in self.adjudications:
                continue
            view = row["experiment_view"]
            source = (self.by_id[row["id"]].get("experiment") or {}).get("level")
            if view["level"] != source:
                wrong.append(row["id"])
            if "adjudication_verdict" in view:
                wrong.append(row["id"])
        self.assertEqual(wrong, [])


# ---------------------------------------------------------------------------
# the adjudication is a derived artefact, not a hand-typed list
# ---------------------------------------------------------------------------

def _art(root, eid, declared, stdout, met=True):
    d = root / "experiments_v2_2" / eid
    d.mkdir(parents=True)
    (d / "result.json").write_text(json.dumps(
        {"expectation": {"declared": declared, "met": met}}, indent=1),
        encoding="utf-8")
    (d / "stdout.txt").write_bytes(stdout)


def _rec(rid, eid, test=None, poc=None, title="some finding", summary=""):
    obs = []
    if test:
        obs.append({"cited_as": test, "experiment_id": eid,
                    "match_kind": "test", "observed": "passed", "test": test})
    if poc:
        obs.append({"cited_as": poc, "experiment_id": eid,
                    "match_kind": "poc_file", "observed": "exit_code=0",
                    "poc_file": poc, "test": None})
    return {"id": rid,
            "finding": {"title": title, "summary": summary, "root_cause": ""},
            "experiment": {"level": "L5", "outcome": "reproduced",
                           "experiment_ids": [eid], "tests_observed": obs,
                           "why_no_L6": "no patched revision exists"}}


class TestAdjudicationIsDerived(unittest.TestCase):
    def _fixture_doc(self):
        tmp = Path(tempfile.mkdtemp())
        (tmp / "jsonl_ml").mkdir()
        recs = [
            _rec("solidity:fixture/A-1", "fix-fail", test="t_fail",
                 title="declared failing property"),
            _rec("solidity:fixture/B-1", "fix-diff",
                 title="differential harness"),
            _rec("solidity:fixture/C-1", "fix-logs", test="t_logs",
                 title="logs observation"),
            _rec("solidity:fixture/D-1", "fix-empty", poc="poc.mjs",
                 title="empty run"),
            _rec("solidity:fixture/E-1", "fix-plain", test="t_plain",
                 title="Reverting thing (NEGATIVE CONTROL)"),
            _rec("solidity:fixture/F-1", "fix-plain", test="t_plain",
                 title="plain all-pass claim"),
            # mixed-case "Negative control:" prose about the FIXED revision is
            # not a self-classification: rule 3(ii) greps the exact tag
            _rec("solidity:fixture/G-1", "fix-plain", test="t_plain",
                 title="another claim",
                 summary="**Negative control:** after the fix it passes."),
        ]
        with (tmp / "jsonl_ml" / "findings_reports.jsonl").open(
                "w", encoding="utf-8") as fh:
            for r in recs:
                fh.write(json.dumps(r) + "\n")
        _art(tmp, "fix-fail", {"fail": ["t_fail"], "min_tests": 1},
             ("Ran 1 test\n[FAIL: vault out of sync: 42 != 0] t_fail() "
              "(gas: 100)\nSuite result: FAILED.\n").encode())
        _art(tmp, "fix-diff",
             {"stdout_contains": ["CHECK pass folded_msg_value"], "min_tests": 0},
             b"CHECK pass folded_msg_value :: rc=0 folded=True\n")
        _art(tmp, "fix-logs", {"all_pass": True, "min_tests": 1},
             ("[PASS] t_logs() (gas: 5)\nLogs:\n  drained = 75000000\n\n"
              "Suite result: ok.\n").encode())
        _art(tmp, "fix-empty", {"all_pass": True, "min_tests": 0}, b"")
        _art(tmp, "fix-plain", {"all_pass": True, "min_tests": 1},
             b"[PASS] t_plain() (gas: 7)\nSuite result: ok.\n")
        return bld.build_document(tmp), recs

    def test_the_builder_produces_the_rule_verdicts_from_fixtures(self):
        doc, _ = self._fixture_doc()
        got = {e["record_id"]: (e["verdict"], e["level_after"])
               for e in doc["adjudications"]}
        self.assertEqual(got["solidity:fixture/A-1"], ("SUPPORTED", "L5"))   # 1a
        self.assertEqual(got["solidity:fixture/B-1"], ("SUPPORTED", "L5"))   # 1b
        self.assertEqual(got["solidity:fixture/C-1"], ("SUPPORTED", "L5"))   # 1c
        self.assertEqual(got["solidity:fixture/D-1"], ("UNSUPPORTED", "L1"))
        self.assertEqual(got["solidity:fixture/E-1"], ("UNSUPPORTED", "L4"))
        self.assertEqual(got["solidity:fixture/F-1"], ("WEAK", "L4"))
        self.assertEqual(got["solidity:fixture/G-1"], ("WEAK", "L4"))
        by_id = {e["record_id"]: e for e in doc["adjudications"]}
        self.assertIn("[FAIL: vault out of sync: 42 != 0]",
                      by_id["solidity:fixture/A-1"]["evidence"])
        self.assertIn("CHECK pass folded_msg_value",
                      by_id["solidity:fixture/B-1"]["evidence"])
        self.assertIn("drained = 75000000",
                      by_id["solidity:fixture/C-1"]["evidence"])
        self.assertIn("insufficient_evidence",
                      by_id["solidity:fixture/D-1"]["reason"])
        self.assertIn("0 bytes", by_id["solidity:fixture/D-1"]["evidence"])
        self.assertIn("negative control", by_id["solidity:fixture/E-1"]["reason"])
        self.assertIn(WEAK_CORE_REASON, by_id["solidity:fixture/F-1"]["reason"])
        self.assertEqual(by_id["solidity:fixture/F-1"]["provisional"], True)
        self.assertEqual(by_id["solidity:fixture/A-1"]["provisional"], False)
        # the generated file passes the downstream fail-closed validators
        tmp = Path(tempfile.mkdtemp()) / "l5_adjudication.json"
        tmp.write_bytes(bld.canonical_bytes(doc))
        _, recs = self._fixture_doc()
        adjs = bd.load_adjudication(tmp)
        bd.check_adjudication(recs, adjs)

    def test_the_committed_file_equals_the_bytes_the_script_produces(self):
        doc = bld.build_document(bld.ROOT)
        self.assertEqual(bld.verify_expected(doc), [],
                         "the artefacts no longer yield the reviewed partition")
        again = bld.build_document(bld.ROOT)
        first, second = bld.canonical_bytes(doc), bld.canonical_bytes(again)
        self.assertEqual(first, second, "regeneration is not byte-deterministic")
        committed = (ROOT / "reports/v2_2/l5_adjudication.json").read_bytes()
        self.assertEqual(committed, first,
                         "the committed adjudication no longer equals the "
                         "bytes scripts/build_v22_l5_adjudication.py produces")
        self.assertNotIn(b"\r\n", committed)

    def test_supported_never_exceeds_what_the_artefact_bytes_show(self):
        """Gate: SUPPORTED is a subset of records whose cited artefact
        contains a `[FAIL` line for a declared-failing test, a numeric
        `Logs:` line, or a met `stdout_contains` expectation. A future edit
        cannot hand-assign L5 again."""
        doc = json.loads(bd.ADJUDICATION.read_text(encoding="utf-8"))
        supported = {e["record_id"] for e in doc["adjudications"]
                     if e["verdict"] == "SUPPORTED"}
        derived = TestRejection._artefact_supported_ids(doc)
        self.assertTrue(supported <= derived,
                        f"SUPPORTED not derivable from artefact bytes: "
                        f"{sorted(supported - derived)}")
        self.assertEqual(supported, SUPPORTED)


if __name__ == "__main__":
    unittest.main(verbosity=2)
