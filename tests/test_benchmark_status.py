"""Tests for the audited benchmark-family status and the scorer's use of it.

The status module exists because the headline set used to be a hand-written
list: a family was in the headline because its name was absent from a
retirement list, not because anything had been measured. These tests pin
the properties that make the new set defensible:

  * a family the independent audit flags cannot enter the primary metric;
  * a family whose scorable rows carry one label has no meaningful
    accuracy, so its accuracy is null with a reason -- never 1.000;
  * a family file nobody has a rule for defaults to non-primary
    (fail-closed), so a new file cannot become the headline by accident;
  * the primary denominator is the sum of the primary families' scorable
    rows, recomputed rather than remembered;
  * a baseline used as a test floor was fitted on train rows only, and its
    fitted label space cannot contain a label that occurs only in the
    held-out split.

The numbers are recomputed from the data on every run: a test that asserted
a fixed count would pass on stale data.
"""
from __future__ import annotations

import collections
import importlib.util
import json
import pathlib
import sys
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(
        name, str(ROOT / "scripts" / f"{name}.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


bstatus = _load("benchmark_status")
scorer = _load("score_benchmark")

BASE = ROOT / "reports" / "baselines"

#: Baseline reports are expensive to build (the retrieval baseline indexes
#: every train row), so they are built once per kind and reused.
_REPORT_CACHE: dict[tuple, dict] = {}


def all_entries(rep):
    """Every scored family, from the four blocks that partition them."""
    out = {}
    for key in ("families", "families_exploratory", "families_invalid",
                "families_retired"):
        out.update(rep[key])
    return out


def cached_baseline_report(kind, seed, fam_data, status):
    key = (kind, seed)
    if key not in _REPORT_CACHE:
        _REPORT_CACHE[key] = scorer.baseline_report(kind, seed,
                                                    fam_data, status)
    return _REPORT_CACHE[key]


class StatusFixture(unittest.TestCase):
    """Shared, computed-once fixtures: the status report and one report."""

    @classmethod
    def setUpClass(cls):
        cls.status = bstatus.status_report(seed=7)
        cls.fam_data = scorer.load_families(cls.status)
        cls._reports = {}
        cls.report = cached_baseline_report("majority", 7, cls.fam_data,
                                            cls.status)

    def status_of(self, fam):
        return self.status["families"][fam]

    def _entry(self, fam):
        """The report entry of a family, whichever block it is in."""
        for key in ("families", "families_exploratory", "families_invalid",
                    "families_retired"):
            if fam in self.report[key]:
                return self.report[key][fam]
        self.fail(f"{fam} is in no block of the report")


class TestStatusComesFromEvidence(StatusFixture):
    def test_every_family_file_on_disk_has_a_status(self):
        """No family may be silently absent from the status report."""
        discovered = bstatus.discover_family_files()
        self.assertTrue(discovered)
        for fam in discovered:
            self.assertIn(fam, self.status["families"],
                          f"{fam} is on disk but has no status")

    def test_a_flagged_family_is_never_primary(self):
        """(a) The primary metric may only contain unflagged families."""
        flagged = [f for f, s in self.status["families"].items()
                   if s["validity_flags"]]
        self.assertTrue(flagged, "no family is flagged: the audit is broken")
        for fam in flagged:
            self.assertNotEqual(self.status_of(fam)["status"],
                                bstatus.STATUS_PRIMARY, fam)

    def test_the_families_the_audit_condemns_are_not_primary(self):
        """R, U and V are shortcut-dominated; C's split has drifted."""
        for fam in ("v3_R_source_tier_routing.jsonl",
                    "vbeta_U_language_routing.jsonl",
                    "vbeta_V_source_tier_routing.jsonl",
                    "C_attacker_reasoning.jsonl"):
            st = self.status_of(fam)
            self.assertNotEqual(st["status"], bstatus.STATUS_PRIMARY, fam)
            self.assertTrue(st["validity_flags"], fam)

    def test_the_primary_metric_contains_no_flagged_family(self):
        """The scorer's headline is the primary set, and nothing else."""
        for fam in self.report["primary_families"]:
            self.assertEqual(self.status_of(fam)["validity_flags"], [], fam)
        primary = set(self.report["primary_families"])
        for fam, st in self.status["families"].items():
            if st["validity_flags"]:
                self.assertNotIn(fam, primary, fam)

    def test_an_unflagged_family_can_still_be_primary(self):
        """The status must not condemn everything: family A is the control."""
        primary = self.status["primary_families"]
        self.assertIn("A_vulnerability_detection.jsonl", primary)
        self.assertEqual(self.status_of("A_vulnerability_detection.jsonl")
                         ["validity_flags"], [])

    def test_shortcut_domination_is_measured_on_train_rows_only(self):
        """U and V are excluded because a train-only shortcut solves them."""
        for fam, floor in (("vbeta_U_language_routing.jsonl", 0.9834),
                           ("vbeta_V_source_tier_routing.jsonl", 0.9998)):
            sf = self.status_of(fam)["shortcut_floor"]
            self.assertEqual(sf["fitted_on"], "train")
            self.assertAlmostEqual(sf["best_train_only_accuracy"], floor,
                                   places=4, msg=fam)
            self.assertNotIn("majority_global_official",
                             sf["train_only_baselines"],
                             "a baseline fitted on the held-out rows is "
                             "not a floor")

    def test_an_unknown_family_defaults_to_non_primary(self):
        """(c) Fail closed: a file with no rule is never primary."""
        fake = "X_family_with_no_rule.jsonl"
        real = bstatus.discover_family_files()
        with mock.patch.object(
                bstatus, "discover_family_files",
                side_effect=lambda: dict(real, **{fake:
                                                  "benchmark/" + fake})):
            rep = bstatus.status_report(seed=7)
        st = rep["families"][fake]
        self.assertEqual(st["status"], bstatus.STATUS_UNKNOWN)
        self.assertNotIn(fake, rep["primary_families"])
        self.assertIn(fake, rep["by_status"][bstatus.STATUS_UNKNOWN])
        self.assertNotIn(fake, rep["by_status"][bstatus.STATUS_PRIMARY])
        self.assertIn("fail-closed", st["reason"])

    def test_the_real_tree_has_no_uncovered_family(self):
        """A family file with no rule would silently drop out of scoring."""
        rep = bstatus.status_report(seed=7)
        self.assertEqual(rep["by_status"][bstatus.STATUS_UNKNOWN], [],
                         "a family file on disk is not covered by any rule")

    def test_status_is_deterministic(self):
        a = json.dumps(bstatus.status_report(seed=7), sort_keys=True)
        b = json.dumps(bstatus.status_report(seed=7), sort_keys=True)
        self.assertEqual(a, b)


class TestSingleLabelFamiliesAreNotEvaluable(StatusFixture):
    def test_single_label_families_report_a_null_accuracy(self):
        """(b) One observed label: no meaningful accuracy, and a reason."""
        single = [f for f, s in self.status["families"].items()
                  if s["n_labels"] == 1 and s["rows_scorable"] > 0]
        self.assertTrue(single, "no single-label family: the rule is untested")
        for fam in single:
            st = self.status_of(fam)
            self.assertFalse(st["evaluable"], fam)
            self.assertEqual(st["evaluable_reason"],
                             "single_label_not_evaluable", fam)
            entry = self._entry(fam)
            self.assertIsNone(entry["accuracy"], fam)
            self.assertIsNone(entry["accuracy_scorable"], fam)
            self.assertEqual(entry["accuracy_reason"],
                             "single_label_not_evaluable", fam)

    def test_the_exploratory_block_publishes_no_1_000(self):
        """The published 1.000 of a single-label family is withdrawn."""
        for fam, entry in self.report["families_exploratory"].items():
            self.assertIsNone(entry["accuracy"], fam)
        micro = self.report["micro_exploratory"]
        self.assertIsNone(micro["accuracy"])
        self.assertIn("single_label_not_evaluable", micro["accuracy_reason"])
        # the rows are still counted: nothing is dropped
        self.assertGreater(micro["scorable"], 0)
        self.assertEqual(
            micro["scorable"],
            sum(e["scorable"] for e in
                self.report["families_exploratory"].values()))

    def test_single_label_families_keep_their_rows_and_labels(self):
        for fam, entry in self.report["families_exploratory"].items():
            st = self.status_of(fam)
            self.assertEqual(entry["scorable"], st["rows_scorable"], fam)
            self.assertTrue(st["label_distribution"], fam)
            self.assertEqual(len(st["label_distribution"]), 1, fam)

    def test_no_accuracy_of_one_survives_anywhere_for_a_single_label_family(
            self):
        """No block may carry a 1.000 for a single-label family."""
        single = {f for f, s in self.status["families"].items()
                  if s["n_labels"] == 1 and s["rows_scorable"] > 0}
        for fam in single:
            entry = self._entry(fam)
            self.assertNotEqual(entry.get("accuracy"), 1.0, fam)
            base = entry.get("baseline") or {}
            for key in ("heldout_test", "heldout_validation"):
                self.assertIsNone(base.get(key, {}).get("accuracy"),
                                 f"{fam} {key}")

    def _entry(self, fam):
        for key in ("families", "families_exploratory", "families_invalid",
                    "families_retired"):
            if fam in self.report[key]:
                return self.report[key][fam]
        self.fail(f"{fam} is in no block of the report")


class TestPrimaryDenominator(StatusFixture):
    def test_denominator_equals_the_primary_families_scorable_rows(self):
        """(d) Recomputed, not remembered."""
        expected = sum(
            len(self.fam_data[f]["rows"])
            for f in self.report["primary_families"])
        self.assertEqual(self.report["primary_denominator"], expected)
        self.assertEqual(self.report["micro"]["scorable"], expected)
        self.assertEqual(
            self.report["micro"]["scorable"],
            sum(e["scorable"] for e in self.report["families"].values()))

    def test_the_denominator_counts_only_primary_families(self):
        primary = set(self.report["primary_families"])
        for key in ("families_exploratory", "families_invalid",
                    "families_retired"):
            for fam in self.report[key]:
                self.assertNotIn(fam, primary, fam)
                self.assertNotIn(fam, self.report["families"], fam)

    def test_every_status_block_reconciles_to_all_families(self):
        blocks = ("families", "families_exploratory", "families_invalid",
                  "families_retired")
        seen = []
        for key in blocks:
            seen.extend(self.report[key])
        self.assertEqual(len(seen), len(set(seen)))
        scored = {f for f, d in self.fam_data.items() if d["rows"]}
        self.assertEqual(set(seen), scored)
        total = sum([self.report["micro"]["scorable"],
                     self.report["micro_exploratory"]["scorable"],
                     self.report["micro_invalid"]["scorable"],
                     self.report["micro_retired"]["scorable"]])
        self.assertEqual(total, self.report["micro_all_families"]["scorable"])

    def test_an_invalid_family_is_reported_not_dropped(self):
        """An invalid family keeps its rows and its numbers."""
        invalid = [f for f, s in self.status["families"].items()
                   if s["status"] == bstatus.STATUS_INVALID]
        self.assertTrue(invalid)
        for fam in invalid:
            entry = self._entry(fam)
            self.assertEqual(entry["status"], bstatus.STATUS_INVALID, fam)
            self.assertEqual(entry["scorable"],
                             self.status_of(fam)["rows_scorable"], fam)

    def test_a_not_scorable_family_carries_a_reason(self):
        for fam, entry in self.report["not_scorable_families"].items():
            self.assertTrue(entry["reason"], fam)
            self.assertEqual(self.status_of(fam)["status"],
                             bstatus.STATUS_NOT_SCORABLE, fam)


class TestBaselinesAreTrainOnly(StatusFixture):
    """(e) A floor fitted on the held-out rows measures nothing."""

    LABEL_FITTING = ("majority", "random", "frequency", "retrieval")

    def test_every_baseline_reports_where_it_was_fitted(self):
        for kind in self.LABEL_FITTING:
            rep = cached_baseline_report(kind, 7, self.fam_data,
                                         self.status)
            self.assertEqual(rep["baseline"]["fitted_on"], "train")
            for fam, entry in all_entries(rep).items():
                base = entry.get("baseline")
                if base is None:
                    continue
                self.assertEqual(base["fitted_on"], "train", f"{kind} {fam}")

    def test_the_reported_train_rows_are_the_train_split(self):
        rep = cached_baseline_report("majority", 7, self.fam_data,
                                     self.status)
        for fam, entry in all_entries(rep).items():
            base = entry.get("baseline")
            if base is None:
                continue
            want = sum(1 for r in self.fam_data[fam]["rows"]
                       if r["split"] == "train")
            self.assertEqual(base["train_rows"], want, fam)

    def test_the_fitted_label_space_excludes_test_only_labels(self):
        """A label that occurs only in the held-out split cannot be in the
        fitted label space: that would mean the floor saw the answer."""
        for kind in self.LABEL_FITTING:
            rep = cached_baseline_report(kind, 7, self.fam_data,
                                         self.status)
            for fam, entry in all_entries(rep).items():
                base = entry.get("baseline")
                if base is None:
                    continue
                rows = self.fam_data[fam]["rows"]
                train_labels = {r["gold"] for r in rows
                                if r["split"] == "train"}
                test_labels = {r["gold"] for r in rows
                               if r["split"] == "test"}
                test_only = test_labels - train_labels
                self.assertEqual(base["test_only_labels"],
                                 sorted(test_only), f"{kind} {fam}")
                self.assertFalse(
                    set(base["fitted_label_space"]) & test_only,
                    f"{kind} {fam}: the fitted label space contains a "
                    f"held-out-only label")

    def test_the_input_heuristics_read_no_label(self):
        for kind in ("first_published", "majority_published"):
            rep = cached_baseline_report(kind, 7, self.fam_data,
                                         self.status)
            self.assertIn("no label", rep["baseline"]["fitted_on"])
            for fam, entry in all_entries(rep).items():
                base = entry.get("baseline")
                if base is None:
                    continue
                self.assertEqual(base["fitted_label_space"], [], f"{kind} {fam}")

    def test_the_held_out_floor_is_computed_on_the_held_out_rows(self):
        """The reported test accuracy is the train-fitted predictor applied
        to the test rows -- recomputed here from the data."""
        rep = cached_baseline_report("majority", 7, self.fam_data,
                                     self.status)
        for fam in self.report["primary_families"]:
            rows = self.fam_data[fam]["rows"]
            train = [r for r in rows if r["split"] == "train"]
            counts = collections.Counter(r["gold"] for r in train)
            best = max(counts.values())
            choice = sorted(g for g, n in counts.items() if n == best)[0]
            test = [r for r in rows if r["split"] == "test"]
            want = sum(1 for r in test if r["gold"] == choice) / len(test)
            got = rep["families"][fam]["baseline"]["heldout_test"]
            self.assertEqual(got["rows"], len(test), fam)
            self.assertAlmostEqual(got["accuracy"], want, places=12, msg=fam)
            self.assertEqual(got["correct"],
                             sum(1 for r in test if r["gold"] == choice), fam)

    def test_a_floor_fitted_on_every_row_would_be_visible(self):
        """R's held-out split carries a label train never saw: the report
        has to name it, or the floor could hide that."""
        fam = "v3_R_source_tier_routing.jsonl"
        rep = cached_baseline_report("majority", 7, self.fam_data,
                                     self.status)
        base = rep["families_invalid"][fam]["baseline"]
        self.assertIn("0", base["test_only_labels"])
        self.assertNotIn("0", base["fitted_label_space"])


class TestCommittedArtefacts(unittest.TestCase):
    """The published reports must equal a regeneration."""

    FAST = ("baseline_majority.json", "baseline_random_seed7.json",
            "baseline_frequency_seed7.json", "baseline_first_published.json",
            "baseline_majority_published.json")

    @classmethod
    def setUpClass(cls):
        cls.status = bstatus.status_report(seed=7)
        cls.fam_data = scorer.load_families(cls.status)
        cls._reports = {}

    def test_the_published_baseline_reports_are_current(self):
        """The five cheap reports are byte-identical to a regeneration.

        The retrieval report is not regenerated here: it costs minutes.
        `python scripts/score_benchmark.py --check` covers all six.
        """
        for fname in self.FAST:
            kind = fname[len("baseline_"):-len(".json")]
            kind = kind[:kind.rindex("_seed")] if "_seed" in kind else kind
            seed = 7
            rep = cached_baseline_report(kind, seed, self.fam_data,
                                         self.status)
            want = scorer.render_report(rep)
            path = BASE / fname
            self.assertTrue(path.is_file(), f"{fname} is missing")
            self.assertEqual(path.read_text(encoding="utf-8"), want,
                             f"{fname} is stale: regenerate with "
                             f"python scripts/score_benchmark.py "
                             f"--build-baselines")

    def test_the_retrieval_report_is_a_train_only_floor(self):
        path = BASE / "baseline_retrieval.json"
        self.assertTrue(path.is_file())
        rep = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(rep["run"], "baseline:retrieval:seed7")
        self.assertEqual(rep["baseline"]["fitted_on"], "train")
        for fam, entry in all_entries(rep).items():
            base = entry.get("baseline")
            if base is None:
                continue
            self.assertEqual(base["fitted_on"], "train", fam)
            self.assertFalse(set(base["fitted_label_space"])
                             & set(base["test_only_labels"]), fam)

    def test_the_published_reports_carry_no_single_label_accuracy(self):
        for path in sorted(BASE.glob("*.json")):
            rep = json.loads(path.read_text(encoding="utf-8"))
            for key in ("families", "families_exploratory", "families_invalid",
                        "families_retired"):
                for fam, entry in (rep.get(key) or {}).items():
                    if entry.get("evaluable") is False:
                        self.assertIsNone(entry.get("accuracy"),
                                          f"{path.name} {fam}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
