"""Invariants for the F-extension (F-A evidence axes, F-B duplicate radar).

The generated files are the artefact under test; the expectations are recomputed
here from the canonical layers, so a builder that quietly changes what a label
means fails these tests instead of failing a count.
"""
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import build_f_extension as fx  # noqa: E402


def rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]


def corpus():
    return rows(ROOT / "derived_rejections" / "rejection_corpus.jsonl")


def fa_rows():
    return rows(ROOT / "benchmark" / "Fa_rejection_evidence_axis_vector.jsonl")


def fb_rows():
    return rows(ROOT / "benchmark" / "Fb_duplicate_radar_pair.jsonl")


def negatives():
    return {r["finding"]["id"]: r for r in rows(ROOT / "jsonl" / "negative_findings.jsonl")}


def findings():
    return {r["finding"]["id"]: r for r in rows(ROOT / "jsonl" / "findings.jsonl")}


JUDGEMENT_TOKENS = (
    "applies", "corroborated", "best_confidence", "is_technical_explanation",
    "technical_refutation", "primary_reason_class", "derived_fact_present",
    "refutes_claim_standing", "gate_on_claim_target", "blocking_condition",
    "why_exploit_fails", "attacker_limitations", "actual_protocol_behavior",
    "claim_standing", "counts_as_technical_reason",
)


class TestFAxisVector(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = {r["finding_id"]: r for r in corpus()}
        cls.rows = fa_rows()

    def test_one_row_per_corpus_record_and_ids_unique(self):
        ids = [r["id"] for r in self.rows]
        self.assertEqual(len(ids), len(set(ids)), "duplicate F-A row ids")
        self.assertEqual({r["source"]["record_id"] for r in self.rows}, set(self.corpus))
        self.assertEqual(len(self.rows), len(self.corpus))

    def test_axis_names_are_the_canonical_six(self):
        import build_rejection_corpus as brc
        self.assertEqual(list(fx.AXES), list(brc.METRICS))
        for row in self.rows:
            self.assertEqual(sorted(row["input"]["axes_to_answer"]), sorted(fx.AXES))

    def test_gold_equals_corpus_metrics(self):
        for row in self.rows:
            record = self.corpus[row["source"]["record_id"]]
            for axis in fx.AXES:
                expected = "supported" if record["metrics"][axis] else "not_supported"
                self.assertEqual(row["answer_key"]["axes"][axis], expected,
                                 f"{row['id']} {axis}")

    def test_axes_are_not_forced_mutually_exclusive(self):
        multi = [r for r in self.rows
                 if sum(1 for a in fx.AXES if r["answer_key"]["axes"][a] == "supported") > 1]
        self.assertTrue(multi, "no record supports more than one axis: overlap was lost")

    def test_duplicate_and_status_are_never_technical(self):
        for row in self.rows:
            technical = row["answer_key"]["technical_explanation_axes"]
            self.assertNotIn(fx.AXES[0], technical)   # publicly reported status
            self.assertNotIn(fx.AXES[3], technical)   # duplicate corroboration
            for axis in technical:
                self.assertIn(axis, fx.TECHNICAL_AXES)

    def test_technical_flag_matches_corpus(self):
        for row in self.rows:
            record = self.corpus[row["source"]["record_id"]]
            expected = bool(record["technical_verification"]
                            ["counts_as_technical_reason_for_why_the_claim_is_false"])
            self.assertEqual(row["answer_key"]["counts_as_technical_reason_for_falsity"],
                             expected, row["id"])

    def test_partial_rows_state_the_missing_evidence(self):
        for row in self.rows:
            if row["answer_key_status"] == "labeled":
                self.assertEqual(row["unassessed_axes"], {})
                self.assertIsNone(row["unlabelled_reason"])
                self.assertEqual(sorted(row["assessed_axes"]), sorted(fx.AXES))
            else:
                self.assertTrue(row["unassessed_axes"], row["id"])
                self.assertTrue(row["unlabelled_reason"], row["id"])
                self.assertNotEqual(row["answer_key_status"], "unlabeled")

    def test_packet_carries_no_derived_conclusion(self):
        for row in self.rows:
            blob = json.dumps(row["input"], sort_keys=True)
            for token in JUDGEMENT_TOKENS:
                self.assertNotIn(f'"{token}"', blob, f"{row['id']} leaks {token}")

    def test_splits_are_inherited_not_re_derived(self):
        # A self-made assignment was the bug this guards: moving records between
        # splits put protected evaluation rows next to their training twins and the
        # leakage check failed. The extension must follow splits_v2 exactly.
        published = fx.published_splits(ROOT / "splits_v2")
        for row in self.rows:
            self.assertEqual(
                row["split"], published.get(row["source"]["record_id"], "unknown"), row["id"])

    def test_row_ids_carry_the_family_key_and_split(self):
        # The shared benchmark row contract (validate_checks.py): an id cannot be
        # moved between splits without changing its identity.
        for row in self.rows:
            self.assertTrue(row["id"].startswith(f"FA::{row['split']}::"), row["id"])
            self.assertEqual(row["id"][len(f"FA::{row['split']}::"):],
                             row["source"]["record_id"])

    def test_unknown_axis_is_allowed_answer(self):
        # unknown_or_insufficient_evidence is a legitimate outcome: the pool must
        # contain it rather than inventing a reason to complete every row.
        supported = sum(1 for r in self.rows
                        if r["answer_key"]["axes"][fx.AXES[5]] == "supported")
        self.assertGreater(supported, 100)


class TestFDuplicateRadar(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = fb_rows()
        cls.negatives = negatives()
        cls.findings = findings()

    def test_ids_unique_and_no_self_pair(self):
        ids = [r["id"] for r in self.rows]
        self.assertEqual(len(ids), len(set(ids)))
        for row in self.rows:
            self.assertNotEqual(row["source"]["candidate_record_id"],
                                row["source"]["comparison_record_id"], row["id"])
            self.assertTrue(row["id"].startswith(f"FB::{row['split']}::"), row["id"])
            self.assertEqual(row["source"]["record_id"],
                             row["source"]["candidate_record_id"])

    def test_positives_rest_on_a_resolved_pointer(self):
        positives = [r for r in self.rows
                     if r["answer_key"]["relationship"] == "same_vulnerability"]
        self.assertTrue(positives)
        for row in positives:
            cid = row["source"]["candidate_record_id"]
            tid = row["source"]["comparison_record_id"]
            pointer = self.negatives[cid]["validation"]["duplicate_of"]
            self.assertEqual(pointer, tid, f"{row['id']} pointer does not match the pair")
            self.assertIn(tid, self.findings, f"{row['id']} target is not an accepted finding")
            self.assertIn(self.findings[tid]["validation"]["status"],
                          ("confirmed", "acknowledged"))

    def test_negatives_have_distinctness_evidence(self):
        for row in self.rows:
            if row["answer_key"]["relationship"] != "distinct_vulnerability":
                continue
            evidence = row["answer_key"]["distinctness_evidence"]
            self.assertTrue(evidence and all(evidence), row["id"])
            cid = row["source"]["candidate_record_id"]
            tid = row["source"]["comparison_record_id"]
            pointer = self.negatives[cid]["validation"].get("duplicate_of")
            if pointer:
                self.assertNotEqual(pointer, tid, f"{row['id']} negative is the pointer target")
            candidate_files = {c["file"] for c in row["input"]["candidate_submission"]
                               ["code_citations"] if c["file"]}
            comparison_files = {c["file"] for c in row["input"]["comparison_finding"]
                                ["code_citations"] if c["file"]}
            self.assertFalse(candidate_files & comparison_files and
                             row["answer_key"]["hardness"] == "different_file",
                             f"{row['id']} labelled different_file but shares a file")

    def test_ambiguous_is_never_counted_as_distinct(self):
        for row in self.rows:
            relationship = row["answer_key"]["relationship"]
            self.assertIn(relationship, fx.PAIR_ANSWERS)
            if relationship == "ambiguous":
                self.assertNotIn("distinctness_evidence", row["input"])
        unresolved = [r for r in self.rows
                      if r["source"]["comparison_record_id"] == "unresolved"]
        for row in unresolved:
            self.assertEqual(row["answer_key_status"], "unlabeled", row["id"])

    def test_input_withholds_label_pointer_and_ids(self):
        for row in self.rows:
            blob = json.dumps(row["input"], sort_keys=True)
            cid = row["source"]["candidate_record_id"]
            tid = row["source"]["comparison_record_id"]
            self.assertNotIn(tid, blob, f"{row['id']} comparison id is in the input")
            pointer = (self.negatives.get(cid, {}).get("validation") or {}).get("duplicate_of")
            if pointer:
                self.assertNotIn(pointer, blob, f"{row['id']} pointer is in the input")
            for status in ("confirmed", "acknowledged", "disputed", "invalid", "nullified"):
                self.assertNotIn(f'"status": "{status}"', blob, f"{row['id']} {status}")
            self.assertFalse(fx.JUDGEMENT_PHRASES.search(
                " ".join(filter(None, [
                    row["input"]["candidate_submission"].get("title"),
                    row["input"]["comparison_finding"].get("title") if isinstance(
                        row["input"]["comparison_finding"], dict) else None]))),
                f"{row['id']} judgement phrase in a title")

    def test_split_is_audit_level_and_never_straddles(self):
        audits: dict[str, set[str]] = {}
        for row in self.rows:
            cid = row["source"]["candidate_record_id"]
            audit = (self.negatives.get(cid) or {}).get("source", {}).get("repository")
            if not audit:
                continue
            audits.setdefault(audit, set()).add(row["split"])
        for audit, splits in audits.items():
            self.assertEqual(len(splits), 1, f"{audit} straddles splits {splits}")
        for split in ("train", "validation", "test"):
            self.assertTrue(any(r["split"] == split for r in self.rows), f"{split} empty")

    def test_no_pair_straddles_splits(self):
        for row in self.rows:
            cid = row["source"]["candidate_record_id"]
            tid = row["source"]["comparison_record_id"]
            candidate_audit = (self.negatives.get(cid) or {}).get("source", {}).get("repository")
            comparison_audit = (self.findings.get(tid) or {}).get("source", {}).get("repository")
            if comparison_audit:
                self.assertEqual(candidate_audit, comparison_audit,
                                 f"{row['id']} pairs across audits")


class TestBuilderContract(unittest.TestCase):
    def test_leak_free_filter(self):
        self.assertFalse(fx.leak_free("Duplicate of #1076"))
        self.assertFalse(fx.leak_free("Not a vulnerability, by design"))
        self.assertTrue(fx.leak_free("Value of asset token can be incorrect"))

    def test_unresolved_target_cannot_be_labeled(self):
        splits = {"a/1": "train"}
        candidate = {"finding": {"id": "a/1"}, "code_context": [], "security_reasoning": {}}
        rows_out, stats, _ = fx.build_fb_rows([], [], [(candidate, None, {
            "pair_class": "ambiguous", "why": "pointer does not resolve"})], {}, splits)
        self.assertEqual(len(rows_out), 1)
        self.assertEqual(rows_out[0]["answer_key_status"], "unlabeled")
        self.assertEqual(rows_out[0]["answer_key"]["relationship"], "ambiguous")

    def test_rows_are_canonically_ordered_and_reproducible(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "build_f_extension.py"), "--check"],
            cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("byte-identical", result.stdout)

    def test_manifest_counts_equal_rows(self):
        manifest = json.loads((ROOT / "benchmark" / "manifest.json")
                               .read_text(encoding="utf-8"))
        for name, loaded in ((fx.FA_NAME, fa_rows), (fx.FB_NAME, fb_rows)):
            entry = manifest["tasks"][name]
            rows_out = loaded()
            self.assertEqual(entry["tasks"], len(rows_out))
            self.assertEqual(entry["labeled"],
                             sum(1 for r in rows_out if r["answer_key_status"] == "labeled"))
            self.assertEqual(entry["unlabeled"],
                             sum(1 for r in rows_out if r["answer_key_status"] == "unlabeled"))
            by_split: dict[str, int] = {}
            for row in rows_out:
                by_split[row["split"]] = by_split.get(row["split"], 0) + 1
            self.assertEqual(entry["by_split"], by_split)

    def test_pairs_are_not_reported_as_independent_submissions(self):
        stats = json.loads((ROOT / "reports" / "f_extension_stats.json")
                           .read_text(encoding="utf-8"))
        self.assertLessEqual(stats["fb"]["unique_candidate_submissions"],
                             stats["fb"]["pair_rows"])
        self.assertNotEqual(stats["fb"]["pair_rows"],
                            stats["fb"]["unique_candidate_submissions"])
        prose = (ROOT / "reports" / "f_extension.md").read_text(encoding="utf-8")
        self.assertIn("unique candidate submissions", prose)


class TestScorer(unittest.TestCase):
    """The scorer must reward an oracle and punish a guesser, or its numbers mean nothing."""

    @classmethod
    def setUpClass(cls):
        import score_f_extension as scorer
        cls.scorer = scorer
        cls.fa = fa_rows()
        cls.fb = fb_rows()

    def test_oracle_scores_perfect_on_both_tracks(self):
        predict = {}
        for row in self.fa:
            predict[row["id"]] = {"axes": row["answer_key"]["axes"],
                                  "technical_explanation_axes":
                                      row["answer_key"]["technical_explanation_axes"]}
        for row in self.fb:
            predict[row["id"]] = {"relationship": row["answer_key"]["relationship"]}
        fa_result = self.scorer.score_fa(self.fa, predict, "oracle")
        fb_result = self.scorer.score_fb(self.fb, predict, "oracle")
        self.assertEqual(fa_result["axis_accuracy"], 1.0)
        self.assertEqual(fa_result["technical_explanation_field"]["exact_match_rate"], 1.0)
        self.assertEqual(
            fa_result["technical_explanation_field"]["answered_duplicate_as_technical"], 0)
        self.assertEqual(
            fa_result["technical_explanation_field"]["answered_status_as_technical"], 0)
        self.assertEqual(fb_result["accuracy"], 1.0)

    def test_unassessed_axis_is_out_of_the_denominator(self):
        row = {"id": "Fa::x", "answer_key_status": "partial",
               "assessed_axes": [fx.AXES[0]],
               "answer_key": {"axes": {a: "supported" for a in fx.AXES},
                              "technical_explanation_axes": []}}
        result = self.scorer.score_fa([row], {"Fa::x": {"axes": {fx.AXES[0]: "supported"},
                                                       "technical_explanation_axes": []}},
                                      "probe")
        self.assertEqual(result["axis_decisions"], 1)
        self.assertEqual(result["per_axis"][fx.AXES[1]]["support"], 0)

    def test_ambiguous_guesser_is_not_a_result(self):
        predict = self.scorer.baseline_predictions(self.fb, "always_ambiguous")
        result = self.scorer.score_fb(self.fb, predict, "always_ambiguous")
        self.assertLess(result["accuracy"], 0.5)
        self.assertEqual(result["confusion"].get("same_vulnerability->ambiguous"),
                         sum(1 for r in self.fb
                             if r["answer_key"]["relationship"] == "same_vulnerability"
                             and r["answer_key_status"] == "labeled"))

    def test_published_baselines_match_recomputation(self):
        published = json.loads((ROOT / "reports" / "f_extension_baselines.json")
                               .read_text(encoding="utf-8"))
        recomputed = [self.scorer.score_fa(self.fa,
                                           self.scorer.baseline_predictions(self.fa, kind), kind)
                      for kind in ("majority_axis", "all_supported", "all_unknown")]
        self.assertEqual(published["fa"]["baselines"], recomputed)
        self.assertEqual(published["fa"]["floor_axis_accuracy"],
                         max(b["axis_accuracy"] or 0 for b in recomputed))


if __name__ == "__main__":
    unittest.main()
