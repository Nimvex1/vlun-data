"""The rejection-evidence layer must keep corroboration, labels and reasons apart.

`derived_rejections/rejection_corpus.jsonl` is the canonical answer to "why was
this submission rejected". `scripts/check_rejection_consistency.py` re-derives
every reported count from its axes, independently of the builder. These tests
run that checker on the real layer, on deliberately broken fixtures, and on the
prose that used to state a duplicate corroboration as if it were a technical
reason.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_rejection_corpus as corpus  # noqa: E402
import check_rejection_consistency as gate  # noqa: E402

CORPUS = ROOT / "derived_rejections" / "rejection_corpus.jsonl"
STATS = ROOT / "reports" / "rejection_evidence_stats.json"
NEGV = ROOT / "reports" / "negative_verification_stats.json"
BROKEN = ROOT / "tests" / "fixtures" / "broken" / "rejection"


def rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in
            path.read_text(encoding="utf-8").splitlines() if line.strip()]


def load_fixture(name: str) -> dict:
    return json.loads((BROKEN / name).read_text(encoding="utf-8"))


class RealLayerIsConsistent(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = rows(CORPUS)
        cls.stats = json.loads(STATS.read_text(encoding="utf-8"))
        cls.negatives = rows(ROOT / "jsonl" / "negative_findings.jsonl")
        cls.view = json.loads(NEGV.read_text(encoding="utf-8")).get("records", [])

    def test_gate_finds_nothing_on_the_real_layer(self):
        bad = gate.check(self.corpus, self.stats, self.negatives, self.view)
        self.assertEqual(bad, [], "; ".join(bad[:5]))

    def test_every_negative_has_exactly_one_row(self):
        self.assertEqual(len(self.corpus), len(self.negatives))
        self.assertEqual({r["finding_id"] for r in self.corpus},
                         {(n["finding"]["id"]) for n in self.negatives})

    def test_the_six_axes_are_documented_and_independent(self):
        self.assertEqual(set(self.stats["metrics"]), set(corpus.METRICS))
        self.assertEqual(set(self.stats["metric_definitions"]), set(corpus.METRICS))
        for name, d in self.stats["metric_definitions"].items():
            self.assertIn(d["counts_as_technical_explanation"], (True, False, "conditional"))
            self.assertTrue(d["means"] and d["note"], name)
        # corroboration and public status are definitionally not explanations
        self.assertFalse(self.stats["metric_definitions"][
            "claim_corroborated_as_duplicate_of_confirmed_finding"
            ]["counts_as_technical_explanation"])
        self.assertFalse(self.stats["metric_definitions"][
            "rejection_status_publicly_reported"]["counts_as_technical_explanation"])
        self.assertGreater(self.stats["metrics"][
            "claim_corroborated_as_duplicate_of_confirmed_finding"],
            self.stats["technical_reason_for_why_the_claim_is_false"],
            "the layer must not present corroboration as the larger explanation count")

    def test_axes_are_not_presented_as_a_sum(self):
        self.assertIn("NOT additive", self.stats["metrics_sum_note"])
        total = sum(self.stats["metrics"].values())
        self.assertNotEqual(total, self.stats["total"])

    def test_original_verdicts_are_carried_verbatim(self):
        by_src = {n["finding"]["id"]: n for n in self.negatives}
        for r in self.corpus:
            v = by_src[r["finding_id"]].get("validation") or {}
            self.assertEqual(r["original_verdict"]["status"], v.get("status"))
            self.assertEqual(r["original_verdict"]["duplicate_of"],
                             v.get("duplicate_of") or None)
            self.assertEqual(r["provenance"]["source_layer"],
                             "jsonl/negative_findings.jsonl")

    def test_technical_reasons_stay_small_and_are_attributable(self):
        tech = [r for r in self.corpus if r["technical_verification"]
                ["counts_as_technical_reason_for_why_the_claim_is_false"]]
        self.assertEqual(len(tech),
                         self.stats["technical_reason_for_why_the_claim_is_false"])
        for r in tech:
            self.assertTrue(set(r["technical_verification"]["bases"])
                            <= set(corpus.TECHNICAL_BASES))

    def test_code_blocker_cites_an_immutable_commit_and_a_verified_declaration(self):
        for r in self.corpus:
            code = r["axes"]["code_supported_reason"]
            if not code["applies"]:
                continue
            self.assertRegex(code["citation"]["audited_commit"], r"^[0-9a-f]{40}$")
            self.assertTrue(code["citation"]["verification"]["verified"], r["finding_id"])
            self.assertTrue(code["citation"]["cited_url_re_pinned"].startswith(
                "https://github.com/"))

    def test_duplicate_corroboration_is_never_a_technical_reason(self):
        for r in self.corpus:
            if "corroborated_duplicate" in r["reason_classes"]:
                self.assertFalse(r["axes"]["duplicate_corroboration"]
                                 ["is_technical_explanation"])
                if r["primary_reason_class"] == "corroborated_duplicate":
                    self.assertFalse(r["technical_verification"]
                                     ["counts_as_technical_reason_for_why_the_claim_is_false"])

    def test_participant_replies_are_recorded_but_not_attributed_as_reasons(self):
        discussed = [r for r in self.corpus if r["axes"]["attributed_reason"]
                     ["participant_statements"]]
        self.assertTrue(discussed)
        for r in discussed:
            for s in r["axes"]["attributed_reason"]["participant_statements"]:
                self.assertFalse(s["counts_as_attributed_reason"])
                self.assertNotIn(s["role"], ("sponsor", "judge"))

    def test_unknown_is_kept_as_an_outcome_not_a_failure(self):
        self.assertGreater(self.stats["metrics"]["unknown_or_insufficient_evidence"], 0)
        unresolved = [r for r in self.corpus if r["unknown_or_insufficient"]]
        for r in unresolved:
            self.assertIn(r["primary_reason_class"], (
                "unresolved", "duplicate_label_unresolved_pointer", "withdrawn_by_author",
                "scope_or_eligibility_label", "dispute_or_invalid_label",
                "unattributed_participant_discussion", "code_gate_context_only"))
            self.assertIsNone(r["is_false_positive"], r["finding_id"])

    def test_reports_do_not_restated_the_old_conflated_count(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertNotIn("defensible reason", readme)
        self.assertIn("rejection_evidence.md", readme)
        v21 = (ROOT / "reports" / "v2_1_quality_report.md").read_text(encoding="utf-8")
        self.assertIn("Negatives with a technical reason why the claim is false", v21)


class BrokenFixturesAreCaught(unittest.TestCase):
    def case(self, name):
        d = load_fixture(name)
        if "row" in d:
            return gate.check_row(d["row"], d.get("source"))
        return gate.check(d["corpus"], d["stats"])

    def test_corroboration_promoted_to_a_technical_reason(self):
        bad = self.case("corroborated_as_technical.json")
        self.assertTrue(any("reason_supported_by_cited_code" in b for b in bad), bad)
        self.assertTrue(any("duplicate corroboration is reported as a technical reason" in b
                            for b in bad), bad)

    def test_false_positive_without_an_executed_disproof(self):
        bad = self.case("false_positive_without_experiment.json")
        self.assertTrue(any("without an executed disproof" in b for b in bad), bad)

    def test_non_false_positive_without_a_resolvable_pointer(self):
        bad = self.case("fp_false_without_pointer.json")
        self.assertTrue(any("without an explicit pointer" in b for b in bad), bad)

    def test_code_blocker_on_a_mutable_citation(self):
        bad = self.case("mutable_gate_citation.json")
        self.assertTrue(any("mutable revision" in b for b in bad), bad)

    def test_altered_verdict_against_the_immutable_layer(self):
        bad = self.case("verdict_overwritten.json")
        self.assertTrue(any("original verdict was altered" in b for b in bad), bad)

    def test_report_that_restates_counts_the_records_do_not_support(self):
        bad = self.case("stats_restated.json")
        self.assertTrue(any("reason_supported_by_cited_code" in b for b in bad), bad)
        self.assertTrue(any("technical_reason" in b for b in bad), bad)


class ProseUsesTheDocumentedAxes(unittest.TestCase):
    def test_generated_prose_is_clean_and_the_history_is_marked(self):
        stats = json.loads(STATS.read_text(encoding="utf-8"))
        self.assertEqual(gate.check_prose(ROOT, stats), [])

    def test_prose_check_fails_on_a_restated_conflated_count(self):
        readme = ROOT / "README.md"
        original = readme.read_text(encoding="utf-8")
        try:
            readme.write_text(original.replace(
                "rejection evidence over 458 rejected submissions",
                "331 negatives with a defensible reason (127 still unknown); "
                "rejection evidence over 458 rejected submissions"), encoding="utf-8")
            stats = json.loads(STATS.read_text(encoding="utf-8"))
            bad = gate.check_prose(ROOT, stats)
            self.assertTrue(any("README.md" in b and "defensible" in b for b in bad), bad)
        finally:
            readme.write_text(original, encoding="utf-8")

    def test_prose_check_fails_when_the_technical_count_drifts(self):
        readme = ROOT / "README.md"
        original = readme.read_text(encoding="utf-8")
        try:
            readme.write_text(original.replace("**6** in total have a technical reason",
                                               "**331** in total have a technical reason"),
                              encoding="utf-8")
            stats = json.loads(STATS.read_text(encoding="utf-8"))
            bad = gate.check_prose(ROOT, stats)
            self.assertTrue(any("README says 331" in b for b in bad), bad)
        finally:
            readme.write_text(original, encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
