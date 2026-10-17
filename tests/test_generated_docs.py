"""Generated-document drift gate.

Three classes of claim had gone stale in documentation while every gate
stayed green, because prose is not gated:

  * a hard-coded check count (README said 101; check_manifests ran 171);
  * Vbeta figures quoted from an older build (U/V task counts, Solodit
    admitted rows, language totals that summed to a different population);
  * a report labelled a live matrix but hand-written months earlier.

This test recomputes each figure from the artefacts it describes and
compares it to what the documents actually say.
"""
from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def jl(p: Path) -> list[dict]:
    return [json.loads(line) for line in p.open(encoding="utf-8") if line.strip()]


class TestReadmeCheckCountIsLive(unittest.TestCase):
    def test_readme_quotes_the_reported_count(self):
        reported = json.loads((ROOT / "reports" / "manifest_checks.json")
                              .read_text(encoding="utf-8"))["checks_total"]
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        m = re.search(r"check_manifests\.py\s+#\s+([\d,]+)\s+count/reference",
                      readme)
        self.assertIsNotNone(m, "README lost the check-count line")
        self.assertEqual(int(m.group(1).replace(",", "")), reported,
                         "README check count is stale; run "
                         "python scripts/generate_readme.py")

    def test_readme_has_no_bare_hardcoded_check_counts(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        stale = re.findall(r"(\d+)\s+count/reference checks", readme)
        reported = json.loads((ROOT / "reports" / "manifest_checks.json")
                              .read_text(encoding="utf-8"))["checks_total"]
        for s in stale:
            self.assertEqual(int(s), reported)


class TestVbetaFiguresAreCurrent(unittest.TestCase):
    def setUp(self):
        self.bench = json.loads(
            (ROOT / "Vbeta" / "benchmark_vbeta" / "vbeta_manifest.json")
            .read_text(encoding="utf-8"))
        self.man = json.loads(
            (ROOT / "Vbeta" / "derived_vbeta" / "manifest.json")
            .read_text(encoding="utf-8"))
        self.records = jl(ROOT / "Vbeta" / "derived_vbeta" / "records.jsonl")

    def test_answer_key_u_and_v_counts(self):
        key = (ROOT / "docs" / "ANSWER_KEY.md").read_text(encoding="utf-8")
        u = self.bench["tasks"]["vbeta_U_language_routing"]
        v = self.bench["tasks"]["vbeta_V_source_tier_routing"]
        self.assertIn(f"{u:,} of {len(self.records):,} admitted", key)
        self.assertIn(f"({v:,}, every admitted record)", key)

    def test_changelog_vbeta_totals(self):
        chg = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn(f"{self.man['candidate_count']:,} candidates / "
                      f"{self.man['record_count']:,} admitted records / "
                      f"{self.man['source_count']} sources", chg)
        # the superseded figures must be gone
        for old in ("844 candidates", "719 admitted records", "12 sources"):
            self.assertNotIn(old, chg, f"stale CHANGELOG figure: {old}")

    def test_solodit_report_counts(self):
        rep = (ROOT / "Vbeta" / "reports_vbeta" / "solodit_ingestion_report.md")
        text = rep.read_text(encoding="utf-8")
        ledger = jl(ROOT / "Vbeta" / "derived_vbeta" / "candidate_ledger.jsonl")
        admitted = {r["finding_id"] for r in self.records}
        sol = [c for c in ledger if c["source_id"] == "solodit-harvest"]
        sol_ad = [c for c in sol if c["candidate_id"] in admitted]
        self.assertIn(f"| Harvested candidates | {len(sol):,} |", text)
        self.assertIn(f"| Admitted records | {len(sol_ad):,} |", text)
        # language totals must be the admitted population and must sum
        import collections
        lang = collections.Counter(c.get("language") for c in sol_ad)
        self.assertIn(f"sum {sum(lang.values()):,}", text)
        self.assertEqual(sum(lang.values()), len(sol_ad))

    def test_build_vbeta_docstring_has_no_stale_source_count(self):
        src = (ROOT / "Vbeta" / "scripts" / "build_vbeta.py").read_text(
            encoding="utf-8")
        self.assertNotIn("newly-verified", src)
        self.assertNotRegex(src, r"harvest \d+ (?:newly-)?verified sources")

    def test_vbeta_manifest_explains_u_gap(self):
        note = self.bench.get("notes", "")
        self.assertIn("unknown", note)
        self.assertIn(f"{len(self.records):,}", note)
        self.assertIn(f"{self.bench['tasks']['vbeta_U_language_routing']:,}", note)


class TestBaselineFiguresInDocsAreLive(unittest.TestCase):
    """The docs quoted pre-retirement numbers (19,662 / 22,148 / 6,218 /
    0.9238) and rendered a zero-prediction baseline as `0.0000 @ 0 tasks`,
    which reads as a scored result. Recompute every figure from the
    committed baseline JSONs and compare to what the docs say."""

    def setUp(self):
        base = ROOT / "reports" / "baselines"
        self.bl = {
            name: json.loads((base / f).read_text(encoding="utf-8"))
            for name, f in (
                ("majority", "baseline_majority.json"),
                ("random-seed7", "baseline_random_seed7.json"),
                ("frequency-seed7", "baseline_frequency_seed7.json"),
                ("first-published", "baseline_first_published.json"),
                ("majority-published", "baseline_majority_published.json"),
                ("retrieval", "baseline_retrieval.json"),
            )
        }
        self.readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.rubric = (ROOT / "docs" / "RUBRIC.md").read_text(
            encoding="utf-8")

    @staticmethod
    def _acc(x):
        return f"{x:.4f}" if isinstance(x, (int, float)) else "n/a"

    def _cell(self, d, scope="micro"):
        m = d[scope]
        return (f"{self._acc(m['accuracy'])} @ {m['predicted']:,}"
                f"/{m['scorable']:,}")

    def test_readme_table_quotes_live_baseline_numbers(self):
        for name in ("majority", "random-seed7", "frequency-seed7",
                     "retrieval"):
            d = self.bl[name]
            self.assertIn(self._cell(d), self.readme, name)
            self.assertIn(f"| {self._cell(d)} | "
                          f"{self._acc(d['micro']['accuracy_scorable'])} |",
                          self.readme, name)
            self.assertIn(self._cell(d, "micro_all_families"), self.readme,
                          name)

    def test_zero_prediction_renders_nav_not_zero(self):
        """first-published emits nothing on the headline set: the docs must
        say n/a at 0/scorable coverage, never 0.0000 @ 0 tasks."""
        d = self.bl["first-published"]
        self.assertIsNone(d["micro"]["accuracy"])
        self.assertEqual(d["micro"]["predicted"], 0)
        cell = self._cell(d)
        self.assertTrue(cell.startswith("n/a @ 0/"), cell)
        self.assertIn(cell, self.readme)
        self.assertIn(cell, self.rubric)
        self.assertIsNone(re.search(r"0\.0000 @\s*0\b", self.readme),
                          "a zero-prediction run is rendered as a scored "
                          "0.0000; run python scripts/generate_readme.py")

    def test_rubric_quotes_live_numbers(self):
        for name in ("majority", "random-seed7", "frequency-seed7",
                     "retrieval"):
            d = self.bl[name]
            m = d["micro"]
            row = (f"| {self._acc(m['accuracy'])} | "
                   f"{self._acc(d['micro_all_families']['accuracy'])} | "
                   f"{m['predicted']:,}/{m['scorable']:,} |")
            self.assertIn(row, self.rubric, name)
        fp = self.bl["first-published"]
        self.assertEqual(fp["micro_all_families"]["accuracy"], 1.0)
        self.assertIn(f"1.000 ({fp['micro_all_families']['predicted']} "
                      f"tasks)", self.rubric)

    def test_superseded_figures_are_gone(self):
        for doc, text in (("README.md", self.readme),
                          ("docs/RUBRIC.md", self.rubric)):
            for old in ("19,662", "22,148", "6,218", "0.9238", "0.9257",
                        "19,663", "19,648"):
                self.assertNotIn(old, text, f"{doc}: stale figure {old}")

    def test_retired_roster_and_rows_are_live(self):
        import sys
        sys.path.insert(0, str(ROOT / "scripts"))
        from vlun import RETIRED_FAMILIES
        from vlun_v3 import V3_FAMILY_FILES

        def letter(name):
            base = name[:-6] if name.endswith(".jsonl") else name
            if base.startswith(("v3_", "vbeta_")):
                return base.split("_")[1]
            return base.split("_")[0]

        def is_retired(key):
            return (f"{key}.jsonl" in RETIRED_FAMILIES
                    or V3_FAMILY_FILES.get(key, "") in RETIRED_FAMILIES)

        letters = ", ".join(sorted({letter(f) for f in RETIRED_FAMILIES}))
        self.assertIn(letters, self.readme)
        self.assertIn(letters, self.rubric)
        ak = (ROOT / "docs" / "ANSWER_KEY.md").read_text(encoding="utf-8")
        self.assertIn(letters, ak)
        btasks = json.loads((ROOT / "benchmark" / "manifest.json")
                            .read_text(encoding="utf-8"))["tasks"]
        vtasks = json.loads((ROOT / "benchmark" / "v3_manifest.json")
                            .read_text(encoding="utf-8"))["tasks"]
        total = 0
        for k, s in btasks.items():
            if is_retired(k):
                total += s.get("scorable", 0) if isinstance(s, dict) else s
        for k, s in vtasks.items():
            if is_retired(k):
                total += s if isinstance(s, int) else s.get("scorable", 0)
        self.assertIn(f"{total:,} scorable rows", self.readme)

    def test_field_coverage_thin_count_is_live(self):
        fc = json.loads((ROOT / "reports" / "field_coverage.json")
                        .read_text(encoding="utf-8"))["fields"]
        thin = sum(
            1 for v in fc.values()
            if isinstance(v, dict)
            and isinstance(v.get("known_pct"), (int, float))
            and v["known_pct"] < 50)
        line = f"{thin} of {len(fc)} tracked fields under 50% known"
        self.assertIn(line, self.readme)
        self.assertIn(
            line, (ROOT / "docs" / "DATASHEET.md").read_text(encoding="utf-8"))

    def test_evaluation_report_and_changelog_quote_live_vbeta_counts(self):
        u = json.loads(
            (ROOT / "Vbeta" / "benchmark_vbeta" / "vbeta_manifest.json")
            .read_text(encoding="utf-8"))["tasks"]["vbeta_U_language_routing"]
        md = (ROOT / "reports" / "independent_benchmark_evaluation.md"
              ).read_text(encoding="utf-8")
        self.assertIn(f"| U | {u} |", md)
        for old in ("22,148", "0.9257", "6218"):
            self.assertNotIn(old, md, f"evaluation report: stale figure {old}")
        chg = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn(f"U ({u:,} tasks)", chg)
        self.assertIn("excludes 716", chg)


class TestExploratoryDemotionIsLive(unittest.TestCase):
    """F, G, I, J (17/7/1/7 scorable rows) are below the 100-row floor for a
    headline family score, so they were demoted from the headline: scored
    per-family and in continuity, never in the headline micro. The docs must
    mark them EXPLORATORY and quote the live headline arithmetic."""

    EXPL = {
        "F_false_positive_rejection.jsonl": 17,
        "G_patch_verification.jsonl": 7,
        "I_verified_non_exploit.jsonl": 1,
        "J_verified_patch.jsonl": 7,
    }

    def setUp(self):
        base = ROOT / "reports" / "baselines"
        self.bl = {n: json.loads((base / f).read_text(encoding="utf-8"))
                   for n, f in (
                       ("majority", "baseline_majority.json"),
                       ("retrieval", "baseline_retrieval.json"),
                       ("first-published", "baseline_first_published.json"))}
        self.readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.rubric = (ROOT / "docs" / "RUBRIC.md").read_text(
            encoding="utf-8")

    def test_headline_and_exploratory_sets_are_disjoint(self):
        for name, d in self.bl.items():
            fams = set(d["families"])
            expl = set(d["families_exploratory"])
            self.assertEqual(expl, set(self.EXPL), name)
            self.assertFalse(fams & expl, name)
            self.assertFalse(
                {k for k, v in d["families_exploratory"].items()
                 if v["scorable"] and k not in self.EXPL}, name)
            self.assertEqual(
                sum(v["scorable"]
                    for v in d["families_exploratory"].values()),
                sum(self.EXPL.values()), name)
            self.assertEqual(d["micro_exploratory"]["scorable"],
                             sum(self.EXPL.values()), name)
            # Demotion must not lose rows: headline + exploratory equals the
            # pre-demotion headline scorable set, and the continuity twin is
            # untouched (headline + exploratory + retired).
            self.assertEqual(
                d["micro"]["scorable"] + d["micro_exploratory"]["scorable"],
                19_663, name)
            self.assertEqual(d["micro_all_families"]["scorable"], 22_149,
                             name)
            self.assertEqual(
                d["micro"]["scorable"] + d["micro_exploratory"]["scorable"]
                + d["micro_retired"]["scorable"], 22_149, name)

    def test_scorer_loads_exploratory_only_for_continuity(self):
        import sys
        sys.path.insert(0, str(ROOT / "scripts"))
        import score_benchmark as sb
        headline = {v[0] for v in sb.load_tasks().values()}
        everything = {v[0] for v in sb.load_tasks(include_retired=True).values()}
        for fam in self.EXPL:
            self.assertNotIn(fam, headline, fam)
            self.assertIn(fam, everything, fam)

    def test_readme_marks_exploratory_not_saturated(self):
        for fam in self.EXPL:
            row = re.search(rf"^\| `{re.escape(fam[:-6])}` \| .* \| EXPLORATORY \|",
                            self.readme, re.M)
            self.assertIsNotNone(row, f"{fam}: README row not marked EXPLORATORY")
        vtasks = json.loads(
            (ROOT / "Vbeta" / "benchmark_vbeta" / "vbeta_manifest.json")
            .read_text(encoding="utf-8"))["tasks"]
        for fam, key in (("vbeta_U_language_routing", "vbeta_U_language_routing"),
                         ("vbeta_V_source_tier_routing",
                          "vbeta_V_source_tier_routing")):
            n = vtasks[key]
            self.assertIn(f"| `{fam}` | {n:,} | {n:,} | SATURATED |",
                          self.readme)

    def test_docs_quote_live_headline_arithmetic(self):
        d = self.bl["majority"]
        self.assertIn(f"covers {d['micro']['scorable']:,} of", self.readme)
        self.assertIn(f"{d['micro']['scorable']:,} tasks", self.rubric)
        self.assertIn(f"{d['micro_all_families']['scorable']:,} tasks",
                      self.rubric)
        self.assertIn(f"{d['micro_exploratory']['scorable']} sub-floor rows",
                      self.rubric)


class TestCountDomainsAreExplicit(unittest.TestCase):
    """candidate_* and admitted_* must name their population, and the
    bare names that mixed the two must be gone."""

    LAYERS = [
        ("derived_v3/manifest.json", "candidate_", "admitted_"),
        ("Vbeta/derived_vbeta/manifest.json", "candidate_", "admitted_"),
    ]

    def test_domains_present_and_self_summing(self):
        for rel, cand_pfx, adm_pfx in self.LAYERS:
            m = json.loads((ROOT / rel).read_text(encoding="utf-8"))
            self.assertIn("count_domains", m, rel)
            cand = [k for k in m if k.startswith(cand_pfx)
                    and isinstance(m[k], dict)]
            adm = [k for k in m if k.startswith(adm_pfx)
                   and isinstance(m[k], dict)]
            self.assertTrue(cand, f"{rel}: no candidate_* distributions")
            self.assertTrue(adm, f"{rel}: no admitted_* distributions")
            for k in cand:
                self.assertEqual(sum(m[k].values()), m["candidate_count"],
                                 f"{rel}:{k}")
            for k in adm:
                self.assertEqual(sum(m[k].values()), m["record_count"],
                                 f"{rel}:{k}")

    def test_ambiguous_bare_names_are_gone(self):
        bare = ("verification_levels", "decisions", "by_source",
                "by_language", "by_ecosystem")
        for rel, _c, _a in self.LAYERS:
            m = json.loads((ROOT / rel).read_text(encoding="utf-8"))
            for k in bare:
                if k in m:
                    self.fail(f"{rel}: ambiguous key '{k}' still present; "
                              f"use candidate_*/admitted_*")


class TestReproducibilityReportIsGenerated(unittest.TestCase):
    def test_report_is_generator_output(self):
        import subprocess
        import sys
        r = subprocess.run([sys.executable,
                            "scripts/build_repro_report.py", "--check"],
                           cwd=str(ROOT), capture_output=True, text=True)
        self.assertEqual(r.returncode, 0,
                         r.stdout + r.stderr +
                         "; run python scripts/build_repro_report.py")

    def test_report_quotes_live_gate_counts(self):
        text = (ROOT / "reports" / "reproducibility_report.md").read_text(
            encoding="utf-8")
        mc = json.loads((ROOT / "reports" / "manifest_checks.json")
                        .read_text(encoding="utf-8"))
        self.assertIn(str(mc["checks_total"]), text)
        self.assertNotIn("119 count/reference checks", text)
        self.assertNotIn("16 provenance/determinism checks", text)

    def test_report_is_machine_independent(self):
        """The CI failure this prevents.

        A checkout WITH the git-ignored V3/clones and work/ runs the
        derived/ rebuild-parity gate; a fresh CI clone skips it. If the
        report embedded that split it would be current on one machine and
        stale on every other. Render it against a synthetic run with the
        opposite profile and require byte-identical output.
        """
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "_br", str(ROOT / "scripts" / "build_repro_report.py"))
        br = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(br)

        real = (ROOT / "reports" / "reproducibility_checks.json")
        backup = real.read_bytes() if real.is_file() else None
        try:
            # CI profile: derived/ parity skipped instead of passed.
            real.write_text(json.dumps({
                "checks": [{"check": "derived/ rebuild parity",
                            "status": "SKIPPED", "detail": "no work/"}],
                "checks_total": 19, "checks_passed": 16,
                "checks_failed": 0, "checks_skipped": 3,
            }, indent=2) + "\n", encoding="utf-8")
            ci = br.render()
        finally:
            if backup is not None:
                real.write_bytes(backup)
        self.assertEqual(ci, br.render(),
                         "report changed when the run profile changed: it is "
                         "embedding machine-dependent results")

    def test_report_has_no_per_check_statuses(self):
        text = (ROOT / "reports" / "reproducibility_report.md").read_text(
            encoding="utf-8")
        for word in ("skipped_no_network:", "| PASS |", "| SKIPPED |"):
            self.assertNotIn(word, text,
                             "per-check statuses are machine-dependent and "
                             "must not be pinned in a committed report")
        self.assertIn("machine-dependent", text)


if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(ROOT / "scripts"))
    unittest.main(verbosity=2)