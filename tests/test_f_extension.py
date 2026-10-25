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

    def test_gold_equals_corpus_metrics_on_assessed_axes_only(self):
        # An unassessable axis gets `unknown`, never a `not_supported` gold: an
        # empty statement list is missing evidence, not proof of absence.
        for row in self.rows:
            record = self.corpus[row["source"]["record_id"]]
            for axis in fx.AXES:
                gold = row["answer_key"]["axes"][axis]
                if axis in row["assessed_axes"]:
                    expected = "supported" if record["metrics"][axis] else "not_supported"
                    self.assertEqual(gold, expected, f"{row['id']} {axis}")
                else:
                    self.assertEqual(gold, "unknown", f"{row['id']} {axis}")
                    self.assertIn(axis, row["answer_key"]["withheld_gold_axes"])

    def test_unassessed_axes_are_documented(self):
        for row in self.rows:
            for axis in row["unassessed_axes"]:
                self.assertIn(axis, fx.AXES, row["id"])
                self.assertNotIn(axis, row["assessed_axes"], row["id"])
                self.assertTrue(row["unassessed_axes"][axis], row["id"])

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

    def test_every_axis_documents_its_assessability_contract(self):
        self.assertEqual(sorted(fx.AXIS_ASSESSABILITY), sorted(fx.AXES))
        for axis, contract in fx.AXIS_ASSESSABILITY.items():
            for field in ("evidence_required", "evidenced_negative", "unassessable_when",
                          "reasoning_kind"):
                self.assertTrue(contract.get(field), f"{axis}.{field}")

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
            self.assertEqual(row["answer_key"]["label_provenance"]["tier"],
                             "pointer_supported_positive", row["id"])

    def test_negatives_need_more_than_a_different_target(self):
        # A different code target alone does not prove a distinct root cause: the
        # primary cohort requires a recorded root-cause difference as well.
        for row in self.rows:
            provenance = row["answer_key"]["label_provenance"]
            if row["answer_key"]["relationship"] != "distinct_vulnerability":
                continue
            self.assertEqual(provenance["tier"],
                             "rule_derived_target_and_root_cause_negative", row["id"])
            self.assertEqual(provenance["cohort"], "primary", row["id"])
            evidence = row["answer_key"]["distinctness_evidence"]
            self.assertTrue(evidence and all(evidence), row["id"])
            self.assertTrue(any("root-cause labels differ" in item for item in evidence),
                            f"{row['id']} distinct without a root-cause difference")
            cid = row["source"]["candidate_record_id"]
            tid = row["source"]["comparison_record_id"]
            pointer = self.negatives[cid]["validation"].get("duplicate_of")
            if pointer:
                self.assertNotEqual(pointer, tid, f"{row['id']} negative is the pointer target")

    def test_target_separation_without_root_cause_is_ambiguous_and_exploratory(self):
        weak = [r for r in self.rows
                if r["answer_key"]["label_provenance"]["tier"]
                == "ambiguous_target_separation_without_root_cause"]
        self.assertTrue(weak)
        for row in weak:
            self.assertEqual(row["answer_key"]["relationship"], "ambiguous", row["id"])
            self.assertEqual(row["answer_key"]["label_provenance"]["cohort"],
                             "exploratory", row["id"])

    def test_no_pair_claims_human_adjudication(self):
        for row in self.rows:
            provenance = row["answer_key"]["label_provenance"]
            self.assertFalse(provenance["human_reviewed"], row["id"])
            self.assertIn(provenance["cohort"], ("primary", "exploratory"), row["id"])

    def test_shared_target_without_a_pointer_is_ambiguous(self):
        shared = [r for r in self.rows
                  if r["answer_key"]["label_provenance"]["tier"]
                  == "ambiguous_shared_target_no_pointer"]
        self.assertTrue(shared)
        for row in shared:
            self.assertEqual(row["answer_key"]["relationship"], "ambiguous", row["id"])

    def test_ambiguous_is_never_counted_as_distinct(self):
        for row in self.rows:
            relationship = row["answer_key"]["relationship"]
            self.assertIn(relationship, fx.PAIR_ANSWERS)
            if relationship == "ambiguous":
                self.assertNotIn("distinctness_evidence", row["input"])

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

    def test_a_shared_target_without_a_pointer_is_not_a_duplicate(self):
        # Different functions can share a root cause, and a shared target is not
        # the same claim: the label must stay ambiguous, not same_vulnerability.
        label = fx.pair_label(shared_target=True)
        self.assertEqual(label["relationship"], "ambiguous")
        self.assertEqual(label["tier"], "ambiguous_shared_target_no_pointer")

    def test_target_separation_without_root_cause_is_exploratory(self):
        label = fx.pair_label(neg_rc="RC-01", fin_rc=None)
        self.assertEqual(label["relationship"], "ambiguous")
        self.assertEqual(label["cohort"], "exploratory")

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

    def test_the_report_does_not_call_rule_derived_labels_adjudicated(self):
        prose = (ROOT / "reports" / "f_extension.md").read_text(encoding="utf-8")
        self.assertNotIn("adjudicated distinct", prose)


def _fb_task(task_id: str, gold: str, split: str = "train") -> dict:
    return {"id": task_id, "split": split, "answer_key_status": "labeled",
            "answer_key": {"relationship": gold, "hardness": "not_applicable"},
            "source": {"candidate_record_id": task_id.split("::")[-1]}}


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
        self.assertEqual(fa_result["micro_accuracy"], 1.0)
        self.assertEqual(fa_result["aggregates"]["all"]["correct_decisions"],
                         fa_result["aggregates"]["all"]["evaluated_decisions"])
        self.assertEqual(fb_result["accuracy"], 1.0)
        self.assertEqual(fb_result["macro_f1"], 1.0)

    def test_unassessed_axis_is_out_of_the_denominator(self):
        row = {"id": "Fa::x", "split": "train", "answer_key_status": "partial",
               "assessed_axes": [fx.AXES[0]],
               "answer_key": {"axes": {a: "supported" for a in fx.AXES},
                              "technical_explanation_axes": []}}
        result = self.scorer.score_fa([row], {"Fa::x": {"axes": {fx.AXES[0]: "supported"},
                                                       "technical_explanation_axes": []}},
                                      "probe")
        self.assertEqual(result["axis_decisions"], 1)
        self.assertEqual(result["per_axis"][fx.AXES[1]]["assessed_decisions"], 0)
        self.assertEqual(result["per_axis"][fx.AXES[1]]["evaluated"], 0)

    def test_a_correct_negative_is_not_a_true_positive(self):
        # The old scorer banked any correct answer as a true positive, so a model
        # that always answered `not_supported` looked perfect.
        row = {"id": "Fa::y", "split": "train", "answer_key_status": "labeled",
               "assessed_axes": [fx.AXES[0]],
               "answer_key": {"axes": {fx.AXES[0]: "not_supported"},
                              "technical_explanation_axes": []}}
        result = self.scorer.score_fa([row], {"Fa::y": {"axes": {fx.AXES[0]: "not_supported"},
                                                       "technical_explanation_axes": []}},
                                      "always_negative")
        block = result["per_axis"][fx.AXES[0]]
        self.assertEqual(block["per_class"]["not_supported"]["tp"], 1)
        self.assertEqual(block["per_class"]["not_supported"]["fp"], 0)
        self.assertEqual(block["per_class"]["not_supported"]["fn"], 0)
        self.assertEqual(block["per_class"]["supported"]["support"], 0)
        self.assertIsNone(block["per_class"]["supported"]["f1"])
        self.assertEqual(block["accuracy"], 1.0)
        self.assertEqual(block["macro_f1"], 1.0)

    def test_missing_prediction_is_a_miss_for_the_gold_class(self):
        row = {"id": "Fa::z", "split": "train", "answer_key_status": "labeled",
               "assessed_axes": [fx.AXES[0]],
               "answer_key": {"axes": {fx.AXES[0]: "supported"},
                              "technical_explanation_axes": []}}
        result = self.scorer.score_fa([row], {}, "silent")
        block = result["per_axis"][fx.AXES[0]]
        self.assertEqual(block["missing_predictions"], 1)
        self.assertEqual(block["per_class"]["supported"]["fn"], 1)
        self.assertEqual(block["per_class"]["supported"]["tp"], 0)
        self.assertEqual(block["accuracy"], 0.0)
        self.assertEqual(result["coverage"]["prediction_coverage"], 0.0)

    def test_malformed_label_is_rejected_not_turned_into_unknown(self):
        row = {"id": "Fa::m", "split": "train", "answer_key_status": "labeled",
               "assessed_axes": [fx.AXES[0]],
               "answer_key": {"axes": {fx.AXES[0]: "supported"},
                              "technical_explanation_axes": []}}
        result = self.scorer.score_fa([row], {"Fa::m": {"axes": {fx.AXES[0]: "probably"},
                                                        "technical_explanation_axes": []}},
                                      "malformed")
        block = result["per_axis"][fx.AXES[0]]
        self.assertEqual(sum(block["invalid_predictions"].values()), 1)
        self.assertEqual(block["valid_predictions"], 0)
        self.assertEqual(result["coverage"]["invalid_predictions"], 1)

    def test_fb_always_distinct_is_scored_against_the_predicted_class(self):
        # 2 same, 2 distinct, 2 ambiguous gold; every pair predicted distinct.
        tasks = []
        for i, gold in enumerate(["same_vulnerability", "distinct_vulnerability", "ambiguous",
                                  "same_vulnerability", "distinct_vulnerability", "ambiguous"]):
            tasks.append(_fb_task(f"FB::t::c{i}", gold))
        predict = {t["id"]: {"relationship": "distinct_vulnerability"} for t in tasks}
        result = self.scorer.score_fb(tasks, predict, "always_distinct", bootstrap=False)
        classes = result["per_class"]
        self.assertEqual(classes["distinct_vulnerability"]["tp"], 2)
        self.assertEqual(classes["distinct_vulnerability"]["fp"], 4)
        self.assertEqual(classes["distinct_vulnerability"]["fn"], 0)
        self.assertEqual(classes["distinct_vulnerability"]["support"], 2)
        self.assertAlmostEqual(classes["distinct_vulnerability"]["precision"], 0.3333, places=4)
        self.assertEqual(classes["distinct_vulnerability"]["recall"], 1.0)
        self.assertAlmostEqual(classes["distinct_vulnerability"]["f1"], 0.5, places=4)
        self.assertEqual(classes["same_vulnerability"]["tp"], 0)
        self.assertEqual(classes["same_vulnerability"]["fn"], 2)
        self.assertEqual(classes["same_vulnerability"]["fp"], 0)
        self.assertEqual(classes["ambiguous"]["fn"], 2)
        self.assertEqual(classes["ambiguous"]["fp"], 0)
        self.assertEqual(result["accuracy"], 0.3333)
        self.assertAlmostEqual(result["macro_f1"], 0.1667, places=4)

    def test_fb_always_same_is_scored_against_the_predicted_class(self):
        tasks = [_fb_task(f"FB::t::s{i}", gold) for i, gold in enumerate(
            ["same_vulnerability", "distinct_vulnerability", "ambiguous"])]
        predict = {t["id"]: {"relationship": "same_vulnerability"} for t in tasks}
        result = self.scorer.score_fb(tasks, predict, "always_same", bootstrap=False)
        classes = result["per_class"]
        self.assertEqual(classes["same_vulnerability"]["tp"], 1)
        self.assertEqual(classes["same_vulnerability"]["fp"], 2)
        self.assertEqual(classes["same_vulnerability"]["fn"], 0)
        self.assertEqual(classes["distinct_vulnerability"]["fn"], 1)
        self.assertEqual(classes["distinct_vulnerability"]["fp"], 0)
        self.assertEqual(classes["ambiguous"]["fn"], 1)
        self.assertEqual(classes["ambiguous"]["fp"], 0)
        self.assertEqual(result["accuracy"], 0.3333)

    def test_fb_always_ambiguous_and_perfect_predictions(self):
        tasks = [_fb_task(f"FB::t::a{i}", gold) for i, gold in enumerate(
            ["same_vulnerability", "distinct_vulnerability", "ambiguous"])]
        ambiguous = self.scorer.score_fb(
            tasks, {t["id"]: {"relationship": "ambiguous"} for t in tasks},
            "always_ambiguous", bootstrap=False)
        self.assertEqual(ambiguous["per_class"]["ambiguous"]["tp"], 1)
        self.assertEqual(ambiguous["per_class"]["ambiguous"]["fp"], 2)
        self.assertEqual(ambiguous["per_class"]["same_vulnerability"]["fn"], 1)
        perfect = self.scorer.score_fb(
            tasks, {t["id"]: {"relationship": t["answer_key"]["relationship"]} for t in tasks},
            "oracle", bootstrap=False)
        self.assertEqual(perfect["accuracy"], 1.0)
        for label in self.scorer.RELATIONS:
            self.assertEqual(perfect["per_class"][label]["fp"], 0)
            self.assertEqual(perfect["per_class"][label]["fn"], 0)
            self.assertEqual(perfect["per_class"][label]["f1"], 1.0)

    def test_fb_missing_and_malformed_predictions_are_not_scored_as_correct(self):
        tasks = [_fb_task(f"FB::t::x{i}", gold) for i, gold in enumerate(
            ["same_vulnerability", "distinct_vulnerability", "ambiguous"])]
        predict = {tasks[0]["id"]: {"relationship": "same_vulnerability"},
                   tasks[1]["id"]: {"relationship": "not_a_class"}}
        result = self.scorer.score_fb(tasks, predict, "partial", bootstrap=False)
        self.assertEqual(result["rows_without_prediction"], 1)
        self.assertEqual(result["rows_invalid_prediction"], 1)
        self.assertEqual(result["per_class"]["same_vulnerability"]["tp"], 1)
        self.assertEqual(result["per_class"]["distinct_vulnerability"]["fn"], 1)
        self.assertEqual(result["per_class"]["ambiguous"]["fn"], 1)
        self.assertEqual(result["accuracy"], 0.3333)
        self.assertLess(result["coverage"]["prediction_coverage"], 1.0)

    def test_fb_absent_class_has_no_denominator(self):
        tasks = [_fb_task("FB::t::only1", "same_vulnerability"),
                 _fb_task("FB::t::only2", "same_vulnerability")]
        result = self.scorer.score_fb(
            tasks, {t["id"]: {"relationship": "same_vulnerability"} for t in tasks},
            "oracle", bootstrap=False)
        for label in ("distinct_vulnerability", "ambiguous"):
            self.assertEqual(result["per_class"][label]["support"], 0)
            self.assertIsNone(result["per_class"][label]["precision"])
            self.assertIsNone(result["per_class"][label]["f1"])

    def test_cluster_bootstrap_is_deterministic(self):
        predict = {row["id"]: {"relationship": row["answer_key"]["relationship"]}
                   for row in self.fb}
        first = self.scorer.cluster_bootstrap(self.fb, predict)
        second = self.scorer.cluster_bootstrap(self.fb, predict)
        self.assertEqual(first, second)
        self.assertTrue(first["available"])
        self.assertEqual(first["seed"], self.scorer.BOOTSTRAP_SEED)
        self.assertEqual(first["unit"], self.scorer.BOOTSTRAP_UNIT)
        self.assertLessEqual(first["accuracy_95ci"][0], first["accuracy_95ci"][1])
        self.assertLessEqual(first["macro_f1_95ci"][0], first["macro_f1_95ci"][1])

    def test_the_frequency_baseline_never_sees_validation_or_test_labels(self):
        tasks = []
        for i in range(4):
            tasks.append({"id": f"FA::train::t{i}", "split": "train",
                          "answer_key_status": "labeled", "assessed_axes": [fx.AXES[0]],
                          "answer_key": {"axes": {fx.AXES[0]: "supported"},
                                         "technical_explanation_axes": []}})
        for i in range(4):
            tasks.append({"id": f"FA::test::t{i}", "split": "test",
                          "answer_key_status": "labeled", "assessed_axes": [fx.AXES[0]],
                          "answer_key": {"axes": {fx.AXES[0]: "not_supported"},
                                         "technical_explanation_axes": []}})
        predictions, meta = self.scorer.frequency_baseline(tasks, "majority_axis")
        self.assertEqual(meta["fit_split"], "train")
        self.assertEqual(meta["fit_rows"], 4)
        self.assertEqual(predictions["FA::test::t0"]["axes"][fx.AXES[0]], "supported")
        self.assertEqual(meta["fitted_counts"][fx.AXES[0]]["supported"], 4)
        self.assertEqual(meta["fitted_counts"][fx.AXES[0]]["not_supported"], 0)

    def test_published_baselines_match_recomputation(self):
        published = json.loads((ROOT / "reports" / "f_extension_baselines.json")
                               .read_text(encoding="utf-8"))
        self.assertIn("fa", published)
        self.assertIn("fb", published)
        fa_predictions = self.scorer.baseline_predictions(self.fa, "majority_axis")
        recomputed = self.scorer.score_fa(self.fa, fa_predictions, "majority_axis",
                                          split="validation")
        self.assertEqual(published["fa"]["frequency_baseline"]["by_split"]["validation"],
                         recomputed)
        fb_predictions = self.scorer.baseline_predictions(self.fb, "majority_pair")
        recomputed_fb = self.scorer.score_fb(self.fb, fb_predictions, "majority_pair",
                                             split="validation")
        self.assertEqual(published["fb"]["frequency_baseline"]["by_split"]["validation"],
                         recomputed_fb)
        # the frequency baseline is fitted on train only, and the floor is the
        # train-fitted predictor on validation - never a maximum over predictors
        # and never a test-selected number
        self.assertEqual(published["fa"]["frequency_baseline"]["fit_split"], "train")
        self.assertEqual(published["fb"]["frequency_baseline"]["fit_split"], "train")
        self.assertEqual(published["fa"]["reference_floor"]["selected_on"], "validation")
        self.assertEqual(published["fb"]["reference_floor"]["selected_on"], "validation")
        self.assertIn("test_reported_not_used_for_selection",
                      published["fa"]["reference_floor"])
        self.assertEqual(published["fa"]["reference_floor"]["micro_accuracy"],
                         recomputed["micro_accuracy"])
        self.assertEqual(published["fb"]["reference_floor"]["micro_accuracy"],
                         recomputed_fb["accuracy"])


if __name__ == "__main__":
    unittest.main()
