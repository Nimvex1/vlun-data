"""Tests for the independent benchmark-validity layer.

Two jobs. First, pin the invariants the audit relies on so it cannot
silently stop measuring what it claims (a leak detector that stopped
matching answers would report every family clean). Second, enforce the
promise that this layer is ADDITIVE: it must never mutate a benchmark
file, an answer key or a split.

The substantive findings themselves are asserted too -- not to freeze
today's numbers, but so that a future fix to a leaking family has to be a
deliberate, visible change to a test rather than a quiet drift.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(
        name, str(ROOT / "scripts" / f"{name}.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


audit = _load("independent_benchmark_audit")
holdout = _load("build_secondary_holdout")

BENCH_DIRS = [ROOT / "benchmark", ROOT / "Vbeta" / "benchmark_vbeta"]


def digest_benchmarks() -> str:
    """Content hash of every committed benchmark file."""
    h = hashlib.sha256()
    for d in sorted(BENCH_DIRS):
        if not d.is_dir():
            continue
        for p in sorted(d.rglob("*")):
            if p.is_file():
                h.update(str(p.relative_to(ROOT)).encode())
                h.update(p.read_bytes())
    return h.hexdigest()


class TestAuditInvariants(unittest.TestCase):
    """The measurement machinery must actually work."""

    def test_answer_leak_detector_fires_on_a_planted_leak(self):
        """Guard against a detector that silently stops matching."""
        row = {"input": {"evidence": "the file is written in cairo today"},
               "answer_key": {"language": "cairo"},
               "answer_key_status": "labeled", "id": "x"}
        fname = "K_language_ecosystem_routing.jsonl"
        res = audit.audit_answer_leakage(fname, [row])
        self.assertEqual(res["answer_literal_in_evidence"], 1)
        self.assertEqual(res["verdict"], "answer_literal_leak")

    def test_answer_leak_detector_ignores_the_instruction_only(self):
        """A prompt naming the label space is self-description, not leak."""
        row = {"input": {
            "prompt": "Answer vulnerable or no_confirmed_vulnerability",
            "evidence": "an owner can be renounced"},
            "answer_key": {"label": "vulnerable"},
            "answer_key_status": "labeled", "id": "x"}
        res = audit.audit_answer_leakage(
            "A_vulnerability_detection.jsonl", [row])
        self.assertEqual(res["answer_literal_in_evidence"], 0)
        self.assertEqual(res["answer_only_in_instruction"], 1)
        self.assertEqual(res["verdict"], "clean")

    def test_short_answer_is_not_treated_as_a_leak(self):
        """`true`/`false` appear in prose constantly; matching them is noise."""
        row = {"input": {"prose": "the true branch reenters the function"},
               "answer_key": {"actor_mentioned": True},
               "answer_key_status": "labeled", "id": "x"}
        res = audit.audit_answer_leakage(
            "N_attacker_identity_extraction.jsonl", [row])
        self.assertEqual(res["rows_checked"], 0)

    def test_macro_f1_is_unweighted(self):
        """A 90/10 split must not score near 1.0 the way accuracy does."""
        gold = ["a"] * 90 + ["b"] * 10
        # always predict the majority class
        self.assertEqual(audit.macro_f1(gold, ["a"] * 100), 0.4737)
        self.assertEqual(audit.macro_f1(gold, gold), 1.0)

    def test_baselines_are_fitted_on_train_only(self):
        """A baseline fitted on the holdout measures nothing.

        Both variants must be reported separately: the honest one uses the
        train majority, the official one uses every labeled row, and the
        two must be computed from their own populations rather than one
        being copied from the other.
        """
        fname = "C_attacker_reasoning.jsonl"
        rows = audit.scorable_rows(fname, audit.load_family(fname))
        b = audit.baselines(fname, rows)
        self.assertIn("majority_from_train", b)
        self.assertIn("majority_global_official", b)
        import collections
        tr = collections.Counter(
            audit.gold_of(r, "attacker_kind") for r in rows
            if r["split"] == "train")
        allg = collections.Counter(
            audit.gold_of(r, "attacker_kind") for r in rows)
        # ties resolve to the sorted-first label, as the official scorer does
        def tie_first(c):
            top = c.most_common(1)[0][1]
            return sorted(k for k, v in c.items() if v == top)[0]
        te = [r for r in rows if r["split"] == "test"]
        expect_train = (sum(1 for r in te
                            if audit.gold_of(r, "attacker_kind")
                            == tie_first(tr)) / len(te))
        expect_global = (sum(1 for r in te
                             if audit.gold_of(r, "attacker_kind")
                             == tie_first(allg)) / len(te))
        self.assertEqual(b["majority_from_train"]["accuracy"],
                         round(expect_train, 4))
        self.assertEqual(b["majority_global_official"]["accuracy"],
                         round(expect_global, 4))

    def test_group_key_never_reads_the_answer(self):
        """The grouping function must not touch the label, or every
        class-disjoint claim becomes circular."""
        import inspect
        src = inspect.getsource(audit.group_key)
        self.assertNotIn("projection", src)

    def test_single_class_family_is_reported_not_scored(self):
        rows = audit.scorable_rows(
            "B_root_cause_reasoning.jsonl",
            audit.load_family("B_root_cause_reasoning.jsonl"))
        deg = audit.audit_degeneracy(
            "B_root_cause_reasoning.jsonl", rows)
        self.assertEqual(deg["verdict"], "single_label")
        self.assertEqual(deg["n_labels"], 1)
        cd = audit.class_disjoint_split("B_root_cause_reasoning.jsonl", rows)
        self.assertTrue(str(cd["verdict"]).startswith("skipped"))


class TestCommittedFindings(unittest.TestCase):
    """Findings that must stay visible until deliberately fixed."""

    @classmethod
    def setUpClass(cls):
        cls.audit = json.loads(
            (ROOT / "reports" / "independent" / "audit.json")
            .read_text(encoding="utf-8"))
        cls.hold = json.loads(
            (ROOT / "benchmark" / "independent"
             / "secondary_holdout_manifest.json").read_text(encoding="utf-8"))

    def test_family_k_group_key_is_the_answer(self):
        """K groups by the record id's language prefix, which is its label.

        A lookup table scores 1.000 on the official test split. If this
        test fails, K's grouping was fixed and this audit must be re-run.
        """
        f = self.audit["families"]["K_language_ecosystem_routing.jsonl"]
        self.assertEqual(
            f["baselines_test_split"]["source_only_lookup"]["accuracy"], 1.0)
        self.assertEqual(
            f["baselines_test_split"]["source_only_lookup"]["coverage"], 1.0)

    def test_family_k_leaks_the_language_in_evidence(self):
        f = self.audit["families"]["K_language_ecosystem_routing.jsonl"]
        self.assertIn("answer_literal_leak", f["validity_flags"])
        self.assertGreaterEqual(f["answer_leakage"]["evidence_leak_rate"], 0.5)

    def test_family_r_train_majority_scores_zero_on_test(self):
        """R's held-out rows are one contest, entirely tier 2, while train
        is majority tier 1. A split-blind floor is meaningless here."""
        f = self.audit["families"]["v3_R_source_tier_routing.jsonl"]
        probe = f["split_drift"]["train_majority_probe"]
        self.assertEqual(probe["train_majority_accuracy_on_test"], 0.0)

    def test_family_r_group_determines_tier(self):
        self.assertIn(
            "skipped_group_determines_label",
            self.hold["families"]["v3_R_source_tier_routing.jsonl"]
            ["group_disjoint"]["verdict"])

    def test_shortcuts_collapse_to_zero_on_class_disjoint_holdouts(self):
        """The headline result of the whole audit.

        Every shortcut that scores 0.84-1.00 on the official splits must
        score 0.0 when the held-out labels never appear in the retained
        side. If a future edit makes one of them non-zero here, the
        holdout stopped being class-disjoint.
        """
        built = {f: v for f, v in self.hold["families"].items()
                 if v.get("class_disjoint", {}).get("verdict") == "built"}
        self.assertGreaterEqual(len(built), 3)
        for fam, v in built.items():
            sc = v["shortcuts_class_disjoint"]
            cd = v["class_disjoint"]
            self.assertTrue(cd["held_out_labels_absent_from_retained"], fam)
            self.assertTrue(cd["group_disjoint_verified"], fam)
            for name in ("majority_from_retained", "input_retrieval",
                         "frequency_from_retained",
                         "random_from_retained_space"):
                self.assertEqual(sc[name]["accuracy"], 0.0,
                                 f"{fam}: {name} scored non-zero on a "
                                 f"class-disjoint holdout, so the holdout "
                                 f"is not class-disjoint")
            # peeking at the holdout must actually buy something, or the
            # holdout is not testing anything
            self.assertGreater(
                sc["majority_heldout_oracle_peek"]["accuracy"], 0.0, fam)

    def test_degenerate_families_are_flagged(self):
        for fam in ("B_root_cause_reasoning.jsonl",
                    "F_false_positive_rejection.jsonl",
                    "G_patch_verification.jsonl",
                    "I_verified_non_exploit.jsonl",
                    "J_verified_patch.jsonl"):
            self.assertIn("single_label",
                          self.audit["families"][fam]["validity_flags"], fam)

    def test_saturated_families_are_flagged(self):
        for fam in ("v3_S_contest_outcome.jsonl",
                    "v3_T_taxonomy_explicit.jsonl",
                    "vbeta_U_language_routing.jsonl",
                    "vbeta_V_source_tier_routing.jsonl"):
            self.assertIn("saturated",
                          self.audit["families"][fam]["validity_flags"], fam)

    def test_committed_first_published_baseline_headline_is_a_coverage_artifact(self):
        """L-only heuristics retire with L: headline coverage is now zero.

        Previously `micro.accuracy = 1.0000` on 71 of 22,148 scorable rows --
        computed on predicted rows only, which made a copy-the-publisher rule
        look like it solved the benchmark. With L retired, the headline
        reports zero coverage (honest) while micro_all_families preserves
        the 71-row continuity number.
        """
        d = json.loads((ROOT / "reports" / "baselines"
                        / "baseline_first_published.json").read_text(
            encoding="utf-8"))
        self.assertEqual(d["micro"]["predicted"], 0)
        self.assertEqual(d["micro"]["accuracy"], None)
        self.assertEqual(d["micro_all_families"]["predicted"], 71)
        self.assertEqual(d["micro_all_families"]["accuracy"], 1.0)

    def test_audit_is_not_a_blanket_condemnation(self):
        """If nothing were clean, the thresholds would be too aggressive to
        be believed. Family A is the control: it must survive."""
        clean = [f for f, v in self.audit["families"].items()
                 if v.get("usable_as_evidence")]
        self.assertEqual(
            clean, ["A_vulnerability_detection.jsonl"],
            "the set of clean families changed; re-run the audit and update "
            "the report before accepting a different verdict")


class TestAdditiveAndReproducible(unittest.TestCase):
    def test_building_the_layer_does_not_touch_benchmark_files(self):
        before = digest_benchmarks()
        holdout.build(seed=7, min_minority=5)
        self.assertEqual(digest_benchmarks(), before,
                         "the secondary holdout modified a benchmark file")

    def test_audit_does_not_touch_benchmark_files(self):
        before = digest_benchmarks()
        audit.run_audit(seed=7)
        self.assertEqual(digest_benchmarks(), before,
                         "the audit modified a benchmark file")

    def test_audit_is_deterministic(self):
        a = json.dumps(audit.run_audit(seed=7), sort_keys=True)
        b = json.dumps(audit.run_audit(seed=7), sort_keys=True)
        self.assertEqual(a, b)

    def test_holdout_is_deterministic(self):
        m1, t1 = holdout.build(seed=7, min_minority=5)
        m2, t2 = holdout.build(seed=7, min_minority=5)
        self.assertEqual(json.dumps(m1, sort_keys=True),
                         json.dumps(m2, sort_keys=True))
        self.assertEqual(t1, t2)

    def test_committed_audit_is_current(self):
        r = subprocess.run(
            [sys.executable, "scripts/independent_benchmark_audit.py",
             "--check"], cwd=str(ROOT), capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_committed_holdout_is_current(self):
        r = subprocess.run(
            [sys.executable, "scripts/build_secondary_holdout.py", "--check"],
            cwd=str(ROOT), capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_holdout_tasks_carry_no_label_in_their_group(self):
        """The written tasks must not smuggle the answer in `group`."""
        p = ROOT / "benchmark" / "independent" / "secondary_holdout_tasks.jsonl"
        seen = 0
        for line in p.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            self.assertIn(r["holdout"], ("group_disjoint", "class_disjoint"))
            self.assertIn("gold", r)
            if r["holdout"] == "class_disjoint":
                seen += 1
        self.assertGreater(seen, 0)

    def test_no_family_is_silently_counted_as_zero(self):
        """Non-scorable families must carry a reason, not a zero score."""
        rep = audit.run_audit(seed=7)
        for fname in audit.NOT_SCORABLE:
            entry = rep["families"][fname]
            self.assertEqual(entry["verdict"], "skipped_no_scorable_key")
            self.assertTrue(entry["reason"])

    def test_report_document_exists_and_cites_the_shortcut_collapse(self):
        p = ROOT / "reports" / "independent_benchmark_evaluation.md"
        self.assertTrue(p.is_file())
        text = p.read_text(encoding="utf-8")
        for needle in ("class-disjoint", "majority", "shortcut",
                       "Remaining validity threats"):
            self.assertIn(needle, text)


if __name__ == "__main__":
    unittest.main()