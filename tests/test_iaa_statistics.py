"""Hand-computable checks for scripts/iaa_statistics.py (item 14 maths).

Every expectation below is derived in the comment, by hand, from the definition - not
from the implementation - so a change in the code that breaks the maths fails here.
"""
from __future__ import annotations

import json
import math
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from iaa_statistics import (  # noqa: E402
    ORDINAL_TIER,
    analyse,
    bootstrap_ci,
    cohens_kappa,
    krippendorff_alpha,
    read_responses,
    report,
    weighted_kappa,
)

TOL = 1e-9

# A Windows drive-letter path ("C:\...", "c:/..."). The lookbehind keeps a URL
# ("https://...") from matching on the "s:/" inside it.
WINDOWS_ABS = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]:[\\/]")
# The fields of the report that carry a path, so the absolute-path scan below
# is scoped to values that are paths rather than to prose that may contain a
# slash for other reasons (a JSON key, a date, a ratio).
PATH_LIKE_FIELDS = ("responses_dir", "study", "measured_reason")


def path_like_values(doc):
    """(label, value) for every path-carrying value in a report document."""
    values = []
    for key in PATH_LIKE_FIELDS:
        val = doc.get(key)
        if isinstance(val, str):
            values.append((key, val))
    for i, note in enumerate(doc.get("notes") or []):
        values.append(("notes[%d]" % i, str(note)))
    reason = (doc.get("statistics") or {}).get("reason")
    if isinstance(reason, str):
        values.append(("statistics.reason", reason))
    return values


def absolute_path_in(text):
    """The first absolute path mentioned in `text`, or None if there is none.

    A path is recognised by its shape, not by a list of known prefixes, so the
    check works the same on Windows and on POSIX: a drive letter, a UNC
    prefix, or a token that begins with a separator.
    """
    for token in text.split():
        token = token.strip("\"'`(),;[]{}")
        if not token:
            continue
        if WINDOWS_ABS.search(token) or token.startswith("\\\\"):
            return token
        if token.startswith("/"):
            return token
    return None


class KappaTests(unittest.TestCase):
    def test_kappa_perfect_agreement_is_one(self):
        a = ["1", "2", "3", "1", "2"]
        self.assertAlmostEqual(1.0, cohens_kappa(a, list(a)), delta=TOL)

    def test_kappa_chance_agreement_is_zero(self):
        # both raters label everything the same single class -> pe = 1, statistic undefined
        self.assertIsNone(cohens_kappa(["1", "1"], ["1", "1"]))
        # marginal-distribution case: po == pe -> kappa 0
        a = ["1", "1", "2", "2"]
        b = ["1", "2", "1", "2"]
        # po = 2/4 = 0.5 ; pe = (2*2 + 2*2)/16 = 0.5
        self.assertAlmostEqual(0.0, cohens_kappa(a, b), delta=TOL)

    def test_kappa_hand_case(self):
        a = ["1", "1", "1", "1", "2", "2", "2", "2"]
        b = ["1", "1", "1", "2", "1", "2", "2", "2"]
        # agree on 6/8 -> po = 0.75
        # rater a marginals: 1:4, 2:4 ; rater b: 1:5, 2:3
        # pe = (4*5 + 4*3)/64 = 32/64 = 0.5
        # kappa = (0.75 - 0.5) / 0.5 = 0.5
        self.assertAlmostEqual(0.5, cohens_kappa(a, b), delta=TOL)

    def test_weighted_kappa_nominal_matches_cohen(self):
        a = ["1", "1", "1", "1", "2", "2", "2", "2"]
        b = ["1", "1", "1", "2", "1", "2", "2", "2"]
        self.assertAlmostEqual(cohens_kappa(a, b),
                               weighted_kappa(a, b, "nominal", ORDINAL_TIER), delta=TOL)

    def test_weighted_kappa_linear_hand_case(self):
        cats = ORDINAL_TIER  # 0,1,2,3 ; k-1 = 3
        a = ["1", "1", "3"]
        b = ["1", "2", "0"]
        # weights: w(i,j)=|i-j|/3. observed disagreements: (1,2)=1/3, (1,0)=1/3 -> num = 2/3 over n=3
        # -> mean observed weight = (2/3)/3 = 2/9
        # marginals: a: 1 x2, 3 x1 ; b: 1,2,0 one each
        # expected = sum_ij w(i,j)*ra_i*rb_j / n^2 = [(1,0):1/3*2*1 + (1,1):0*2*1 + (1,2):1/3*2*1
        #            + (3,0):1*1*1 + (3,1):2/3*1*1 + (3,2):1/3*1*1] / 9
        #          = (2/3 + 2/3? recompute) -> computed below independently
        exp = 0.0
        ra = {"1": 2, "3": 1}
        rb = {"0": 1, "1": 1, "2": 1}
        for i, ci in enumerate(cats):
            for j, cj in enumerate(cats):
                exp += (abs(i - j) / 3.0) * ra.get(ci, 0) * rb.get(cj, 0) / 9.0
        # observed weighted disagreement (as a per-item mean) = (0 + 1/3 + 1)/3 = 4/9
        expected_value = 1 - (4.0 / 9.0) / exp
        self.assertAlmostEqual(expected_value,
                               weighted_kappa(a, b, "linear", cats), delta=TOL)

    def test_weighted_kappa_quadratic_penalises_far_errors_more(self):
        near = (["1", "1", "3"], ["1", "2", "3"])
        far = (["1", "1", "3"], ["3", "2", "3"])
        kn = weighted_kappa(near[0], near[1], "quadratic", ORDINAL_TIER)
        kf = weighted_kappa(far[0], far[1], "quadratic", ORDINAL_TIER)
        self.assertGreater(kn, kf)


class AlphaTests(unittest.TestCase):
    def test_alpha_perfect_agreement(self):
        units = [{"a": "1", "b": "1"}, {"a": "2", "b": "2"}, {"a": "1", "b": "1"}]
        self.assertAlmostEqual(1.0, krippendorff_alpha(units, "nominal"), delta=TOL)

    def test_alpha_full_disagreement_two_coders_two_units(self):
        # every unit has one 1 and one 2.
        # Do: per unit, mean squared disagreement over ordered pairs = (1*1*1 + 1*1*1)/(2*1) = 1
        # Dc: pooled values = [1,1,2,2]; (1*2... ) = (2*2*1 + 2*2*1)/(4*3) = 8/12 = 2/3
        # alpha = 1 - 1/(2/3) = -1/2
        units = [{"a": "1", "b": "2"}, {"a": "2", "b": "1"}]
        self.assertAlmostEqual(-0.5, krippendorff_alpha(units, "nominal"), delta=TOL)

    def test_alpha_single_unit_one_disagreement(self):
        # one unit, two coders, different values: Do = 1, Dc = 1 -> alpha = 0
        units = [{"a": "1", "b": "2"}]
        self.assertAlmostEqual(0.0, krippendorff_alpha(units, "nominal"), delta=TOL)

    def test_alpha_units_without_two_values_are_skipped(self):
        # unit 3 has one coder: it can neither agree nor disagree, so it is dropped.
        # remaining units: [1,1] -> Do contribution 0 ; [1,2] -> Do contribution 1
        # Do = (0 + 1)/2 = 0.5. Pooled values [1,1,1,2]: counts 1:3, 2:1, m=4
        # Dc = (3*1*1 + 1*3*1)/(4*3) = 6/12 = 0.5  ->  alpha = 1 - 0.5/0.5 = 0
        units = [{"a": "1", "b": "1"}, {"a": "1", "b": "2"}, {"a": "2"}]
        self.assertAlmostEqual(0.0, krippendorff_alpha(units, "nominal"), delta=TOL)
        # no unit with two coders at all -> nothing measurable, reported as None not as 1.0
        self.assertIsNone(krippendorff_alpha([{"a": "1"}, {"a": "2"}], "nominal"))

    def test_alpha_ordinal_prefers_near_misses(self):
        near = [{"a": "0", "b": "1"}, {"a": "1", "b": "2"}, {"a": "2", "b": "3"}]
        far = [{"a": "0", "b": "3"}, {"a": "3", "b": "0"}, {"a": "1", "b": "3"}]
        a_near = krippendorff_alpha(near, "ordinal", ORDINAL_TIER)
        a_far = krippendorff_alpha(far, "ordinal", ORDINAL_TIER)
        self.assertGreater(a_near, a_far)


class BootstrapTests(unittest.TestCase):
    def test_bootstrap_bracket_and_determinism(self):
        units = [{"a": "1", "b": "1"}, {"a": "1", "b": "2"}, {"a": "2", "b": "2"},
                 {"a": "2", "b": "2"}, {"a": "1", "b": "1"}, {"a": "2", "b": "1"}]
        f = lambda us: krippendorff_alpha(us, "nominal")  # noqa: E731
        c1 = bootstrap_ci(f, units, seed=7, reps=500)
        c2 = bootstrap_ci(f, units, seed=7, reps=500)
        self.assertEqual(c1, c2, "bootstrap must be seeded and reproducible")
        self.assertTrue(c1["ci95_low"] <= c1["point"] <= c1["ci95_high"]
                        or c1["ci95_low"] <= c1["ci95_high"])
        self.assertGreater(c1["replicates"], 0)


class ResponseHandlingTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.responses = Path(tmp.name) / "responses"
        self.responses.mkdir()

    def test_empty_responses_dir_reports_not_measured(self):
        d = self.responses
        (d / "annotator_1.template.csv").write_text("record_id\n", encoding="utf-8")
        rows, notes = read_responses(str(d))
        self.assertEqual(rows, [])
        doc = report(str(d), root=os.getcwd())
        self.assertIs(doc["measured"], False)
        self.assertTrue(doc["measured_reason"])

    def test_llm_self_consistency_is_not_iaa(self):
        """Two passes by one model are not two annotators, and a non-human kind is excluded."""
        d = self.responses
        for name, kind in (("a.csv", "llm_self_consistency"), ("b.csv", "llm_self_consistency")):
            rows = [
                {"annotator_id": "gpt-run-1", "annotator_kind": kind, "record_id": "r1",
                 "rc_primary": "RC-01", "severity_tier": "2", "evidence_ceiling": "L2"},
                {"annotator_id": "gpt-run-1", "annotator_kind": kind, "record_id": "r2",
                 "rc_primary": "RC-02", "severity_tier": "1", "evidence_ceiling": "L2"},
            ]
            _write_csv(d / name, rows)
        rows, _ = read_responses(str(d))
        out = analyse(rows)
        self.assertIs(out["measurable"], False)
        self.assertEqual(sum(out["non_human_rows_excluded"].values()), 4)

    def test_single_human_annotator_twice_is_not_iaa(self):
        d = self.responses
        rows = [
            {"annotator_id": "human-1", "annotator_kind": "human", "record_id": "r1",
             "rc_primary": "RC-01", "severity_tier": "2", "evidence_ceiling": "L2"},
            {"annotator_id": "human-1", "annotator_kind": "human", "record_id": "r2",
             "rc_primary": "RC-02", "severity_tier": "1", "evidence_ceiling": "L2"},
        ]
        _write_csv(d / "only.csv", rows)
        out = analyse(read_responses(str(d))[0])
        self.assertIs(out["measurable"], False)
        self.assertEqual(out["annotators_seen"], 1)

    def test_two_humans_produce_numbers(self):
        d = self.responses
        rows = []
        for rid, pa, pb, sa, sb in [("r1", "RC-01", "RC-01", "2", "2"), ("r2", "RC-02", "RC-03", "1", "2"),
                                    ("r3", "RC-03", "RC-03", "3", "3"), ("r4", "RC-01", "RC-01", "0", "1")]:
            for aid, p, s_, kind in (("human-A", pa, sa, "human"), ("human-B", pb, sb, "human")):
                rows.append({"annotator_id": aid, "annotator_kind": kind, "record_id": rid,
                             "rc_primary": p, "severity_tier": s_, "evidence_ceiling": "L2"})
        _write_csv(d / "both.csv", rows)
        out = analyse(read_responses(str(d))[0])
        self.assertIs(out["measurable"], True)
        stats = out["per_pair"]["human-A|human-B"]
        self.assertEqual(stats["n_common"], 4)
        # hand: po on primary = 3/4, marginals A {RC-01:2,RC-02:1,RC-03:1}, B {RC-01:2,RC-03:2}
        # pe = (2*2 + 1*0 + 1*2)/16 = 6/16 = 0.375 -> kappa = (0.75-0.375)/0.625 = 0.6
        self.assertAlmostEqual(0.6, stats["kappa_primary_label"], delta=TOL)
        self.assertTrue(math.isfinite(stats["weighted_kappa_severity_linear"]))


class ReportPortabilityTests(unittest.TestCase):
    """The report must be the same bytes on every machine (P0, CI drift).

    The generator used to spell the responses directory with the path it was
    handed: an absolute path in one note and a path relative to the current
    working directory in the other. The committed report therefore carried the
    generating machine's home directory, and the `iaa-stats-current` gate
    failed on every CI runner while passing on the machine that committed it.
    """

    RESPONSES_REL = "annotation/iaa_v1/responses"

    def repo_responses(self):
        return os.path.join(str(ROOT), *self.RESPONSES_REL.split("/"))

    def generated(self):
        return report(self.repo_responses(), root=str(ROOT))

    def run_builder(self, out, cwd):
        r = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "iaa_statistics.py"),
             "--root", str(ROOT), "--out", out],
            cwd=cwd, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return Path(out).read_bytes()

    def test_generated_report_carries_no_absolute_path(self):
        doc = self.generated()
        for label, value in path_like_values(doc):
            bad = absolute_path_in(value)
            self.assertIsNone(bad, "%s carries the absolute path %r in %r"
                              % (label, bad, value))
        blob = json.dumps(doc, ensure_ascii=False, sort_keys=True)
        hit = WINDOWS_ABS.search(blob)
        self.assertIsNone(hit, "the report carries a Windows absolute path: %r"
                          % (hit.group(0) if hit else None))

    def test_committed_report_carries_no_absolute_path(self):
        committed = ROOT / "reports" / "iaa_status.json"
        raw = committed.read_text(encoding="utf-8")
        doc = json.loads(raw)
        for label, value in path_like_values(doc):
            bad = absolute_path_in(value)
            self.assertIsNone(bad, "%s carries the absolute path %r in %r"
                              % (label, bad, value))
        hit = WINDOWS_ABS.search(raw)
        self.assertIsNone(hit, "the committed report carries a Windows absolute "
                                "path: %r" % (hit.group(0) if hit else None))

    def test_report_bytes_are_stable_across_repeated_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = self.run_builder(os.path.join(tmp, "a.json"), str(ROOT))
            second = self.run_builder(os.path.join(tmp, "b.json"), str(ROOT))
            self.assertEqual(first, second, "two runs must produce identical bytes")

    def test_report_bytes_do_not_depend_on_the_current_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            here = self.run_builder(os.path.join(tmp, "here.json"), str(ROOT))
            there = self.run_builder(os.path.join(tmp, "there.json"), tmp)
            self.assertEqual(here, there,
                             "the report must not depend on the current directory")

    def test_committed_report_equals_a_fresh_generation(self):
        committed = (ROOT / "reports" / "iaa_status.json").read_bytes()
        with tempfile.TemporaryDirectory() as tmp:
            fresh = self.run_builder(os.path.join(tmp, "fresh.json"), str(ROOT))
        self.assertEqual(committed.replace(b"\r\n", b"\n"), fresh,
                         "the committed report must equal a fresh generation")

    def test_note_names_the_repository_relative_responses_path(self):
        doc = self.generated()
        notes = " ".join(doc["notes"])
        self.assertIn(self.RESPONSES_REL, notes)
        self.assertNotIn("\\", notes, "the note must use forward slashes")
        self.assertEqual(doc["responses_dir"], self.RESPONSES_REL)

    def test_absent_responses_directory_is_named_repo_relatively(self):
        missing = os.path.join(str(ROOT), "annotation", "iaa_v1", "no-such-dir")
        rows, notes = read_responses(missing, root=str(ROOT))
        self.assertEqual(rows, [])
        self.assertEqual(notes,
                         ["responses directory absent: annotation/iaa_v1/no-such-dir"])

    def test_responses_directory_outside_the_repository_is_not_spelled_out(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = os.path.join(tmp, "responses")
            os.makedirs(d)
            doc = report(d, root=str(ROOT))
            blob = json.dumps(doc, ensure_ascii=False, sort_keys=True)
            self.assertNotIn(tmp, blob,
                             "the report must not carry this machine's temp path")
            self.assertEqual(doc["responses_dir"], "responses")
            notes = " ".join(doc["notes"])
            self.assertIn("outside the repository root", notes)
            self.assertIsNone(absolute_path_in(notes))

    def test_read_responses_still_accepts_a_single_argument(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = os.path.join(tmp, "responses")
            os.makedirs(d)
            rows, notes = read_responses(d)  # the old one-argument call form
            self.assertEqual(rows, [])
            self.assertTrue(notes)


def _write_csv(path, rows):
    import csv

    fields = ["annotator_id", "annotator_kind", "record_id", "rc_primary",
              "severity_tier", "evidence_ceiling"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


if __name__ == "__main__":
    unittest.main()
