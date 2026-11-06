#!/usr/bin/env python3
"""Every consumer of a v2.2 verification claim must read the ADJUDICATED view.

`jsonl_ml/` is immutable, so all 35 records whose source experiment claimed L5
still say `experiment.level == "L5"` and `finding.status ==
"experimentally_verified"` there, even the 31 that the artefact-grounded
re-adjudication (reports/v2_2/l5_adjudication.json) demoted to L4/L1. An audit
found three consumers reading that source layer directly and publishing the
withdrawn claim through a second path:

    Fix 1  scripts/build_canonical_training.py `harvest_v22`  -> detection rows
           labelled `verified` off the raw status
    Fix 2  scripts/build_benchmark_v22.py `task_m`            -> family M's
           answer key off the raw experiment block
    Fix 3  scripts/build_benchmark_v22.py `task_q`            -> family Q's
           per-field evidence types off the raw evidence map

Fix 4 closes the same class where it starts: `build_derived_v22` now restates
`outcome`/`evidence_type` for EVERY view below L5, adjudicated or not, which is
what `vyper:CVE-2024-24567` (L3, `reproduced`, never visited by the
adjudication) needed. Fix 5 bounds `quality.verification` with the closed set
`schema_terms.QUALITY_VERIFICATION_STATES` so a bucket typo cannot ship.

These are pure reads plus in-memory rebuilds: nothing here writes a layer, and
nothing here rewrites the frozen rows under `benchmark/retired_families/`,
which are published history built while the source claim still stood.

Run:  python -m unittest tests.test_v22_adjudicated_consumers -v
"""
from __future__ import annotations

import collections
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_benchmark_v22 as bb  # noqa: E402
import build_canonical_training as bct  # noqa: E402
import build_derived_v22 as bd  # noqa: E402
import schema_terms as T  # noqa: E402
from vlun import RETIRED_FAMILIES, read_jsonl  # noqa: E402

CVE_L3 = "vyper:CVE-2024-24567"
SPLITS = ("train", "validation", "test")


def published_records() -> dict[str, dict]:
    return {r["id"]: r for r in
            read_jsonl(ROOT / "derived_v2_2" / "records.jsonl")}


def source_findings() -> dict[str, dict]:
    out = {}
    for path in sorted((ROOT / "jsonl_ml").glob("findings_*.jsonl")):
        for row in read_jsonl(path):
            out[row["id"]] = row
    return out


class LayerBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records = published_records()
        cls.findings = source_findings()
        cls.adjudications = bd.load_adjudication()
        cls.demoted = {rid for rid, e in cls.adjudications.items()
                       if e["level_after"] != "L5"}
        assert len(cls.demoted) == 30, "the adjudication no longer demotes 30 records"


# ---------------------------------------------------------------------------
# Fix 4 -- a record below L5 never asserts reproduction, adjudicated or not
# ---------------------------------------------------------------------------

class TestSubL5Restatement(LayerBase):
    def rebuilt(self, rid: str) -> dict:
        return bd.build_record(self.findings[rid], {}, self.adjudications)

    def rebuilt_with_registry(self, rid, registry):
        return bd.build_record(self.findings[rid], registry, self.adjudications)

    def test_the_l3_record_is_restated_without_touching_its_level(self):
        rec = self.records[CVE_L3]
        view = rec["experiment_view"]
        # what the committed layer publishes today (pre-fix, by design of the
        # test: it proves the restatement is the delta, not the level)
        self.assertEqual(view["level"], "L3")
        row = self.rebuilt(CVE_L3)
        new = row["experiment_view"]
        self.assertEqual(new["level"], "L3",
                         "Fix 4 must not move a level: only make the fields "
                         "agree with it")
        self.assertEqual(new["outcome"], bd.OUTCOME_EXECUTED_NOT_DEMONSTRATED)
        self.assertEqual(new["evidence_type"], "observed_fact")
        self.assertEqual(new["outcome_before_adjudication"], "reproduced")
        self.assertEqual(new["evidence_type_before_adjudication"],
                         "experimentally_verified")
        self.assertTrue(new["source_refs"],
                        "a restated observed_fact must still point at bytes")
        self.assertIn("sub_l5_restatement", new)
        # and the summary follows the view
        self.assertNotIn("experimentally_verified",
                         row["evidence_summary"]["counts"])
        self.assertEqual(row["evidence_summary"]["strongest"], "observed_fact")
        # No "differs from the committed layer" assertion here: the committed
        # layer is already the restated one, so it would assert a disagreement
        # that the fix exists to remove. The invariant is in the lines above.

    def test_no_rebuilt_view_below_l5_disagrees_with_its_own_outcome(self):
        _findings, registry = bd.load_layer()
        bad = []
        for f in _findings:
            row = bd.build_record(f, registry, self.adjudications)
            bad += bd.level_outcome_disagreements(row)
        self.assertEqual(bad, [],
                         "a rebuilt record still asserts reproduction below L5")

    def test_the_gate_predicate_is_red_on_a_disagreement(self):
        """Fail-closed: the predicate catches a claim the restatement missed."""
        fake = {"id": "synthetic:one",
                "experiment_view": {"present": True, "level": "L4",
                                    "outcome": "reproduced",
                                    "evidence_type": "experimentally_verified",
                                    "artefacts_all_present": True},
                "evidence_summary": {"counts": {"experimentally_verified": 2}},
                "quality": {"verification": "experimentally_verified"}}
        found = bd.level_outcome_disagreements(fake)
        self.assertEqual(len(found), 4, found)
        self.assertTrue(all("synthetic:one" in p for p in found))
        # the same record at L5, or restated, is clean
        fake["experiment_view"]["level"] = "L5"
        self.assertEqual(bd.level_outcome_disagreements(fake), [])
        fake["experiment_view"]["level"] = "L4"
        fake["experiment_view"].update({
            "outcome": bd.OUTCOME_EXECUTED_NOT_DEMONSTRATED,
            "evidence_type": "observed_fact"})
        fake["evidence_summary"] = {"counts": {"observed_fact": 2}}
        fake["quality"] = {"verification": "executed_not_demonstrated"}
        self.assertEqual(bd.level_outcome_disagreements(fake), [])

    def test_no_level_at_all_is_treated_as_below_l5(self):
        self.assertTrue(bd.below_l5(None))
        self.assertTrue(bd.below_l5("L4"))
        self.assertFalse(bd.below_l5("L5"))
        self.assertFalse(bd.below_l5("L6"))
        out = bd.restate_below_l5(
            {"present": True, "level": None, "outcome": "reproduced",
             "evidence_type": "experimentally_verified", "artefacts": []},
            "test")
        self.assertEqual(out["outcome"], bd.OUTCOME_NO_COMMITTED_OBSERVATION)
        self.assertEqual(out["evidence_type"], "reported_claim")

    def test_the_general_gate_restates_exactly_as_a_demotion_does(self):
        """Same level in, same strings out -- adjudicated or not."""
        adjudicated = self.rebuilt("solidity:zentory-self-audit/O-01")
        synthetic = bd.restate_below_l5(
            {"present": True, "level": "L4", "outcome": "reproduced",
             "evidence_type": "experimentally_verified", "artefacts":
             [{"path": "experiments_v2_2/x/result.json", "exists": True}]},
            "test")
        view = adjudicated["experiment_view"]
        for field in ("outcome", "evidence_type"):
            self.assertEqual(synthetic[field], view[field], field)

    def test_the_level_census_is_unchanged(self):
        """Fix 4 must not promote or demote anything."""
        _findings, registry = bd.load_layer()
        counts = collections.Counter(
            (bd.build_record(f, registry, self.adjudications)["experiment_view"]
             ["level"] or "none") for f in _findings)
        self.assertEqual(dict(counts),
                         {"L1": 1, "L3": 1, "L4": 29, "L5": 5, "L6": 1,
                          "none": 100})

    def test_only_the_expected_published_bytes_move(self):
        """The restatement delta is auditable and bounded.

        Measured against each SOURCE record's own claim, not against the
        committed derived layer: that layer already carries the restatement, so
        comparing with it would report an empty delta and prove nothing.
        """
        _findings, registry = bd.load_layer()
        moved_semantics, audit_only = [], []
        for f in _findings:
            row = bd.build_record(f, registry, self.adjudications)
            claims = (f.get("experiment") or {}).get("outcome") == "reproduced"
            restated = (row["experiment_view"].get("outcome")
                        in (bd.OUTCOME_EXECUTED_NOT_DEMONSTRATED,
                            bd.OUTCOME_NO_COMMITTED_OBSERVATION))
            if claims and restated:
                moved_semantics.append(row["id"])
            elif (row["experiment_view"].get("outcome_before_adjudication")
                  and not restated):
                audit_only.append(row["id"])
        self.assertEqual(sorted(moved_semantics),
                         sorted([CVE_L3] + list(self.demoted)),
                         "exactly the 30 demoted records plus the one L3 "
                         "record had a reproduction claim restated")
        self.assertEqual(audit_only, [])


# ---------------------------------------------------------------------------
# Fix 5 -- quality.verification is a closed set
# ---------------------------------------------------------------------------

class TestClosedVerificationVocabulary(LayerBase):
    def test_the_vocabulary_names_the_new_bucket(self):
        self.assertIn("executed_not_demonstrated",
                      T.QUALITY_VERIFICATION_STATES)
        self.assertEqual(
            set(T.QUALITY_VERIFICATION_STATES),
            {"experimentally_verified", "executed_not_demonstrated",
             "incomplete", "reported_claim", "unverified"})

    def test_the_builder_emits_only_listed_buckets(self):
        self.assertEqual(bd.VERIFICATION_LABELS, T.QUALITY_VERIFICATION_STATES)
        emitted = {(r.get("quality") or {}).get("verification")
                   for r in self.records.values()}
        self.assertTrue(emitted <= set(T.QUALITY_VERIFICATION_STATES), emitted)
        self.assertIn("executed_not_demonstrated", emitted)

    def test_a_bucket_typo_is_rejected(self):
        self.assertEqual(
            T.check_quality_verification_state("executed_not_demonstrated",
                                               "test"),
            "executed_not_demonstrated")
        with self.assertRaises(T.TerminologyError):
            T.check_quality_verification_state("executed_notDemonstrated",
                                               "test")
        with self.assertRaises(T.TerminologyError):
            T.check_quality_verification_state("verified", "test")

    def test_the_published_rubric_describes_every_bucket(self):
        """Family Q's rubric is the model-facing dictionary of these labels."""
        rule = bb.QUALITY_RUBRIC["verification"]
        for bucket in T.QUALITY_VERIFICATION_STATES:
            self.assertIn(bucket, rule, f"{bucket} is in the vocabulary but "
                                       "not described by the published rubric")

    def test_the_gate_checks_the_layer(self):
        from validate import Report
        import validate_checks as vc
        rep = Report(quiet=True)
        vc.check_v22_layer(rep)
        names = {c["check"] for c in rep.checks}
        for required in ("quality_verification_in_closed_vocabulary",
                         "no_sub_l5_reproduction_claim",
                         "benchmark_retired_v22_rows_are_frozen",
                         "family_M_answers_follow_the_adjudication"):
            self.assertIn(required, names)


# ---------------------------------------------------------------------------
# Fix 2 -- family M's answer key is the adjudicated view, and the guard
# ---------------------------------------------------------------------------

class TestFamilyMFollowsAdjudication(LayerBase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.tasks, cls.info = bb.build()
        cls.rows = cls.tasks["M"]

    def test_the_builder_still_reads_the_raw_claim_nowhere_in_the_answer(self):
        self.assertEqual(self.info["problems"], [],
                         "; ".join(self.info["problems"][:5]))
        self.assertEqual(len(self.rows), 37)
        raw_positives = 0
        for row in self.rows:
            rid = row["source"]["record_id"]
            view = self.info["derived_records"][rid]["experiment_view"]
            self.assertEqual(row["answer_key"]["level"], view["level"],
                             row["id"])
            self.assertEqual(row["answer_key"]["outcome"], view["outcome"],
                             row["id"])
            self.assertEqual(row["answer_key"]["evidence_type"],
                             view["evidence_type"], row["id"])
            if rid in self.demoted:
                raw_positives += 1
                # the immutable source row still says L5; the key may not
                self.assertEqual(
                    self.findings[rid]["experiment"]["level"], "L5", rid)
                self.assertNotEqual(row["answer_key"]["level"], "L5",
                                    f"{rid}: family M re-published the "
                                    "withdrawn L5 claim")
        self.assertEqual(raw_positives, 30)

    def test_the_rebuilt_key_census_is_the_adjudicated_one(self):
        levels = collections.Counter(r["answer_key"]["level"] for r in self.rows)
        self.assertEqual(dict(levels),
                         {"L1": 1, "L3": 1, "L4": 29, "L5": 5, "L6": 1})
        self.assertNotIn("experimentally_verified",
                         {r["answer_key"]["evidence_type"]
                          for r in self.rows if r["answer_key"]["level"] == "L4"})

    def test_the_guard_refuses_a_key_that_is_not_the_adjudicated_level(self):
        """Red/green proof of the fail-closed guard family M needs live."""
        bad_row = json.loads(json.dumps(
            next(r for r in self.rows
                 if r["source"]["record_id"] in self.demoted)))
        rid = bad_row["source"]["record_id"]
        self.assertNotEqual(bad_row["answer_key"]["level"], "L5", rid)
        bad_row["answer_key"]["level"] = "L5"          # the withdrawn claim
        bad_row["answer_key"]["evidence_type"] = "experimentally_verified"
        problems = bb.m_answer_key_problems([bad_row], self.info["derived_records"])
        self.assertTrue(problems, "the guard let a raw L5 answer through")
        self.assertIn("answer_key.level", problems[0])
        self.assertIn(rid, problems[0])

    def test_family_m_is_still_retired(self):
        self.assertIn("M_experiment_level_classification.jsonl",
                      RETIRED_FAMILIES,
                      "this remediation does not un-retire family M")

    def test_the_retired_copy_is_untouched(self):
        """The frozen rows are published history: no rebuild rewrites them."""
        path = (ROOT / "benchmark" / "retired_families"
                / "M_experiment_level_classification.jsonl")
        before = path.read_bytes()
        bb.build()                       # the rebuild must not write anything
        self.assertEqual(path.read_bytes(), before,
                         "a rebuild touched the frozen family M rows")
        frozen = read_jsonl(path)
        levels = collections.Counter(
            r["answer_key"]["level"] for r in frozen)
        self.assertEqual(levels["L5"], 35,
                         "the frozen rows were rewritten away from the "
                         "pre-adjudication claim they published")
        self.assertEqual(
            {r["answer_key"]["evidence_type"] for r in frozen},
            {"experimentally_verified"})
        # ... and the live builder disagrees with them by design: 30 answers
        # because the adjudication moved the level below L5, plus
        # `vyper:CVE-2024-24567`, whose level was ALREADY L3 while its evidence
        # type read `experimentally_verified` (the frozen row publishes that
        # contradiction; the live builder may not).
        differing = {
            r["source"]["record_id"]
            for r in self.rows
            if r["answer_key"] != next(f for f in frozen if f["id"] == r["id"])
            ["answer_key"]}
        self.assertEqual(len(differing), 31)
        self.assertIn("vyper:CVE-2024-24567", differing)

    def test_no_write_path_targets_retired_families(self):
        """Not one frozen family file moves, whatever the rebuild produces."""
        directory = ROOT / "benchmark" / "retired_families"
        before = {p.name: p.read_bytes() for p in sorted(directory.glob("*.jsonl"))}
        self.assertTrue(before, "no retired family files found")
        bb.build()
        self.assertEqual({p.name: p.read_bytes()
                          for p in sorted(directory.glob("*.jsonl"))}, before,
                         "a rebuild rewrote published history")


# ---------------------------------------------------------------------------
# Fix 3 -- family Q's per-field evidence types are the adjudicated ones
# ---------------------------------------------------------------------------

class TestFamilyQFieldTypes(LayerBase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.tasks, cls.info = bb.build()
        cls.q = {r["id"]: r for r in cls.tasks["Q"]}

    def test_q_answers_are_pinned_to_the_published_layer(self):
        """Every Q answer key equals derived_v2_2/records.jsonl, all 137 rows."""
        self.assertEqual(len(self.q), 137)
        for rid_row, row in self.q.items():
            rec_id = row["source"]["record_id"]
            rec = self.records[rec_id]
            answer = row["answer_key"]
            self.assertEqual(
                answer["field_evidence_types"],
                bd.field_evidence_types(self.findings[rec_id].get("evidence")
                                        or {}, rec["experiment_view"]),
                rid_row)
            self.assertEqual(answer["strongest"],
                             rec["evidence_summary"]["strongest"], rid_row)
            self.assertEqual(answer["weakest"],
                             rec["evidence_summary"]["weakest"], rid_row)
            for k, v in answer["quality"].items():
                self.assertEqual(v, rec["quality"][k], f"{rid_row} {k}")

    def test_the_per_field_types_are_the_types_the_summary_counts(self):
        for row in self.tasks["Q"]:
            rec = self.records[row["source"]["record_id"]]
            counted = collections.Counter(
                row["answer_key"]["field_evidence_types"].values())
            self.assertEqual(dict(counted), rec["evidence_summary"]["counts"],
                             row["id"])

    def test_the_35_adjudicated_records_never_type_a_run_experimentally(self):
        checked = 0
        for rid, entry in self.adjudications.items():
            if entry["level_after"] == "L5":
                continue
            checked += 1
            for row in self.tasks["Q"]:
                if row["source"]["record_id"] != rid:
                    continue
                types = row["answer_key"]["field_evidence_types"]
                for field, et in types.items():
                    self.assertNotEqual(
                        et, "experimentally_verified",
                        f"{rid}.{field} still claims an experiment at level "
                        f"{entry['level_after']}")
        self.assertEqual(checked, 30)

    def test_the_raw_map_still_says_what_the_source_claimed(self):
        """The immutable source is not edited; only the answer follows the view."""
        raw = self.findings["solidity:zentory-self-audit/M-09"]["evidence"]
        self.assertEqual(raw["poc_execution"]["evidence_type"],
                         "experimentally_verified")
        demoted_view = self.records["solidity:zentory-self-audit/M-09"][
            "experiment_view"]
        self.assertEqual(demoted_view["level"], "L1")
        self.assertEqual(
            bd.field_evidence_types(raw, demoted_view)["poc_execution"],
            demoted_view["evidence_type"])


# ---------------------------------------------------------------------------
# Fix 1 -- canonical detection labels follow the adjudicated level
# ---------------------------------------------------------------------------

class TestCanonicalDetectionFollowsLevel(LayerBase):
    def test_no_published_v22_detection_positive_is_below_l5(self):
        b = bct.Builder()
        bct.harvest_v22(b)
        positives = [r for r in b.rows
                     if r["task"] == "detection" and r["label"] is True]
        for r in positives:
            view = self.records[r["canonical_id"]]["experiment_view"]
            if view.get("present"):
                self.assertIn(view.get("level"), bct.DETECTION_LEVELS,
                              f"{r['canonical_id']} is a verified positive at "
                              f"level {view.get('level')}")
        # 30 adjudicated demotions + vyper:CVE-2024-24567 (L3, never visited by
        # the adjudication) all still carry the raw status the gate used to read
        self.assertEqual(b.excluded["v2.2:detection_below_l5"], 31,
                         "31 records must leave the verified set")
        withdrawn = self.demoted | {CVE_L3}
        raw_positives = {rid for rid, rec in self.records.items()
                         if rec["finding"]["status"] in
                         ("confirmed", "experimentally_verified")}
        self.assertEqual(raw_positives - {r["canonical_id"] for r in positives},
                         withdrawn)
        self.assertFalse({r["canonical_id"] for r in positives} & withdrawn)

    def test_a_demoted_row_is_excluded_never_relabelled_a_negative(self):
        b = bct.Builder()
        bct.harvest_v22(b)
        negatives = [r for r in b.rows
                     if r["task"] == "detection" and r["label"] is False]
        self.assertEqual({r["canonical_id"] for r in negatives}
                         & self.demoted, set(),
                         "a demotion is not evidence that the finding is false")

    def test_unit_fixture_for_the_level_gate(self):
        """The gate itself, on synthetic rows: no layer is read or written."""

        def rec(rid, status, level, present, record_class="vulnerability"):
            return {"id": rid, "language": "solidity",
                    "finding": {"id": rid, "status": status, "severity": None,
                                "record_class": record_class,
                                "title": f"crafted fixture {rid}",
                                "vulnerability_classes": []},
                    "experiment_view": {"present": present, "level": level,
                                        "outcome": None, "evidence_type": None},
                    "code_context_view": {"citations": 0, "resolved": 0}}

        rows = [
            rec("x:L5", "experimentally_verified", "L5", True),
            rec("x:L6", "experimentally_verified", "L6", True),
            rec("x:L4", "experimentally_verified", "L4", True),
            rec("x:L1", "experimentally_verified", "L1", True),
            rec("x:nolevel", "experimentally_verified", None, True),
            rec("x:judged", "confirmed", None, False),
            rec("x:neg", "reported_claim", None, False, "negative_control"),
        ]
        ids = {r["id"] for r in rows}
        self.assertEqual(len(ids), len(rows))
        real_read = bct.read_jsonl

        def fake_read(path: Path):
            name = path.as_posix()
            if "splits_v2_2" in name:
                split = path.stem
                return [{"id": r["id"], "layer": "v2.2", "split": split}
                        for r in rows if split == "train"]
            if "derived_v2_2" in name:
                return rows
            return real_read(path)

        bct.read_jsonl = fake_read
        try:
            b = bct.Builder()
            bct.harvest_v22(b)
        finally:
            bct.read_jsonl = real_read
        positives = {r["canonical_id"]: r for r in b.rows
                     if r["task"] == "detection" and r["label"] is True}
        negatives = {r["canonical_id"] for r in b.rows
                     if r["task"] == "detection" and r["label"] is False}
        self.assertEqual(set(positives), {"x:L5", "x:L6", "x:judged"})
        self.assertEqual(positives["x:L5"]["verification_level"], "L5")
        self.assertEqual(positives["x:L6"]["verification_level"], "L6")
        self.assertEqual(positives["x:judged"]["verification_level"], "unknown",
                         "a record with no experiment behind it is not gated "
                         "by a level it never claimed")
        self.assertEqual(negatives, {"x:neg"})
        self.assertEqual(b.excluded["v2.2:detection_below_l5"], 3,
                         "L4, L1 and an experiment with no level at all are "
                         "each excluded")


if __name__ == "__main__":
    unittest.main(verbosity=2)
