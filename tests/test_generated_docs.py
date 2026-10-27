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
    """The family statuses are computed from the data at run time
    (`scripts/benchmark_status.py`), so the headline set is decided by
    measurements, not by a list. F, G, I, J are demoted to EXPLORATORY and
    C, R, U, V are INVALID; only A is PRIMARY. The docs must mark them with
    the audited status and quote the live headline arithmetic."""

    EXPL = {
        "F_false_positive_rejection.jsonl",
        "G_patch_verification.jsonl",
        "I_verified_non_exploit.jsonl",
        "J_verified_patch.jsonl",
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

    def test_primary_exploratory_and_invalid_sets_are_disjoint(self):
        """The status-derived invariant that replaced the old row arithmetic.

        The retired assertion `primary + exploratory == 19,663` encoded the
        OLD scheme, in which the headline set was "every family that is not
        retired and has at least 100 rows". The audit-driven statuses
        removed that invariant by design, so it is replaced by one that is
        derived from the report's own `family_status` block:

          * the primary, exploratory, invalid and retired blocks are pairwise
            disjoint;
          * their union is exactly the set of families the scorer knows about
            that have scorable rows -- nothing is silently dropped;
          * each block's membership agrees with the status the status block
            records for that family;
          * no family the status block flags INVALID is in the primary set.
        """
        for name, d in self.bl.items():
            status = d["family_status"]
            primary = set(d["families"])
            expl = set(d["families_exploratory"])
            invalid = set(d["families_invalid"])
            retired = set(d["families_retired"])
            blocks = (primary, expl, invalid, retired)
            for i, a in enumerate(blocks):
                for b in blocks[i + 1:]:
                    self.assertFalse(a & b, f"{name}: {a & b} is in two blocks")
            scored = {f for f, s in status.items() if s.get("rows_scorable")}
            self.assertEqual(primary | expl | invalid | retired, scored,
                             f"{name}: the blocks do not cover every scored "
                             f"family")
            for f in primary:
                self.assertEqual(status[f]["status"], "PRIMARY",
                                 f"{name}: {f} is in the primary block but "
                                 f"its status is {status[f]['status']}")
            for f in expl:
                self.assertEqual(status[f]["status"], "EXPLORATORY",
                                 f"{name}: {f} is in the exploratory block but "
                                 f"its status is {status[f]['status']}")
            for f in invalid:
                self.assertEqual(status[f]["status"], "INVALID",
                                 f"{name}: {f} is in the invalid block but "
                                 f"its status is {status[f]['status']}")
            for f in retired:
                self.assertTrue(status[f]["retired"],
                                f"{name}: {f} is in the retired block but is "
                                f"not marked retired")
            flagged = {f for f, s in status.items()
                       if s["status"] == "INVALID"}
            self.assertFalse(primary & flagged,
                             f"{name}: an invalid family is in the primary set")
            self.assertEqual(expl, set(self.EXPL), name)

    def test_no_shortcut_dominated_family_is_primary(self):
        """A family a train-only shortcut solves is not evaluation evidence.

        The threshold comes from the report's own `status_thresholds`, so
        this fails if a shortcut-dominated family ever enters the primary
        set -- the failure the old row arithmetic could not see, because it
        only counted rows.
        """
        for name, d in self.bl.items():
            thr = d["status_thresholds"]["shortcut_dominance_accuracy"]
            min_holdout = d["status_thresholds"]["min_shortcut_holdout_rows"]
            for fam in d["families"]:
                st = d["family_status"][fam]
                floor = (st.get("shortcut_floor") or {})
                best = floor.get("best_train_only_accuracy")
                heldout = floor.get("heldout_rows") or 0
                if isinstance(best, (int, float)) and heldout >= min_holdout:
                    self.assertLess(
                        best, thr,
                        f"{name}: {fam} is solved by a train-only shortcut "
                        f"({best}) but is in the primary set")
                self.assertFalse(st.get("validity_flags"),
                                 f"{name}: {fam} carries validity flags "
                                 f"{st.get('validity_flags')} but is primary")
                self.assertGreaterEqual(
                    st.get("rows_scorable") or 0,
                    d["status_thresholds"]["min_primary_rows"],
                    f"{name}: {fam} is below the headline floor but is primary")
                self.assertGreaterEqual(
                    st.get("n_labels") or 0,
                    d["status_thresholds"]["min_labels"],
                    f"{name}: {fam} has fewer than two observed labels but is "
                    f"primary")

    def test_single_label_families_report_no_accuracy(self):
        """A family with one observed label has no meaningful accuracy.

        Its accuracy must be null with the stated reason in every block --
        otherwise a 1.000 would be published as predictive performance when
        it is only the label distribution restated.
        """
        for name, d in self.bl.items():
            for block in ("families", "families_exploratory",
                          "families_invalid", "families_retired"):
                for fam, entry in d[block].items():
                    st = d["family_status"][fam]
                    if st.get("evaluable"):
                        continue
                    self.assertIsNone(
                        entry.get("accuracy"),
                        f"{name}: {fam} has one observed label but reports an "
                        f"accuracy of {entry.get('accuracy')!r}")
                    self.assertIsNone(entry.get("accuracy_scorable"),
                                      f"{name}: {fam}")
                    self.assertIn("single_label_not_evaluable",
                                  str(entry.get("accuracy_reason")),
                                  f"{name}: {fam}")
            # a block whose families are all single-label has no accuracy
            for fams, micro in (("families_exploratory", "micro_exploratory"),
                                ("families", "micro"),
                                ("families_invalid", "micro_invalid"),
                                ("families_retired", "micro_retired")):
                entries = d[fams]
                if entries and all(
                        not d["family_status"][f].get("evaluable")
                        for f in entries):
                    self.assertIsNone(
                        d[micro].get("accuracy"),
                        f"{name}: {micro} has no evaluable family but reports "
                        f"an accuracy")

    def test_scorer_loads_exploratory_only_for_continuity(self):
        import sys
        sys.path.insert(0, str(ROOT / "scripts"))
        import score_benchmark as sb
        headline = {v[0] for v in sb.load_tasks().values()}
        everything = {v[0] for v in sb.load_tasks(include_retired=True).values()}
        for fam in self.EXPL:
            self.assertNotIn(fam, headline, fam)
            self.assertIn(fam, everything, fam)

    def test_readme_marks_the_audited_status(self):
        """The README's family table must carry the audited status.

        The old scheme (RETIRED / EXPLORATORY / SATURATED) is gone: a family
        is PRIMARY, EXPLORATORY, INVALID or NOT_SCORABLE, and retirement is
        a location rather than a verdict.
        """
        import sys
        sys.path.insert(0, str(ROOT / "scripts"))
        from vlun_v3 import V3_FAMILY_FILES
        file_to_key = {v: k for k, v in V3_FAMILY_FILES.items()}

        def key_of(fam_file):
            if fam_file in file_to_key:
                return file_to_key[fam_file]
            return (fam_file[:-6] if fam_file.endswith(".jsonl")
                    else fam_file)

        for fam in self.EXPL:
            row = re.search(rf"^\| `{re.escape(fam[:-6])}` \| .* \| EXPLORATORY \|",
                            self.readme, re.M)
            self.assertIsNotNone(row, f"{fam}: README row not marked EXPLORATORY")
        for name, d in self.bl.items():
            for fam, st in d["family_status"].items():
                key = key_of(fam)
                row = re.search(
                    rf"^\| `{re.escape(key)}` \| [\d,]+ \| [\d,]+ \| "
                    rf"([A-Z_]+) \|", self.readme, re.M)
                self.assertIsNotNone(row, f"{name}: no README row for {key}")
                self.assertEqual(row.group(1), st["status"],
                                 f"{name}: README marks {key} as "
                                 f"{row.group(1)}, the status block says "
                                 f"{st['status']}")

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

    def test_report_renders_on_a_fresh_clone(self):
        """The doc test must pass with the git-ignored snapshot ABSENT.

        Regression (2026-10-25): the reproducibility row was rendered from
        reports/reproducibility_checks.json, a machine-local file that only
        exists after someone runs the gate. A fresh clone (or the first
        standalone `python -m unittest discover -s tests`) rendered the row
        as SKIPPED, the --check failed, and the documented verification
        command did not pass on the tree it documents. The counts now come
        from the committed summary.
        """
        import subprocess
        import sys
        snap = ROOT / "reports" / "reproducibility_checks.json"
        backup = snap.read_bytes() if snap.is_file() else None
        if snap.is_file():
            snap.unlink()
        try:
            r = subprocess.run([sys.executable,
                                "scripts/build_repro_report.py", "--check"],
                               cwd=str(ROOT), capture_output=True,
                               text=True, timeout=300)
            self.assertEqual(
                r.returncode, 0,
                "build_repro_report --check must pass without the "
                "machine-local snapshot: " + r.stdout + r.stderr)
        finally:
            if backup is not None:
                snap.write_bytes(backup)

    def test_the_reproducibility_counts_are_committed_and_status_free(self):
        import subprocess
        summary = ROOT / "reports" / "reproducibility_checks_summary.json"
        self.assertTrue(summary.is_file())
        tracked = subprocess.run(
            ["git", "ls-files", "--error-unmatch",
             "reports/reproducibility_checks_summary.json"],
            cwd=str(ROOT), capture_output=True, text=True)
        self.assertEqual(
            tracked.returncode, 0,
            "the counts summary must be in the git index: a fresh clone "
            "cannot render the report without it")
        doc = json.loads(summary.read_text(encoding="utf-8"))
        self.assertIn("checks_total", doc)
        self.assertIn("checks_failed_critical", doc)
        for banned in ("checks", "checks_passed", "checks_skipped",
                       "rebuild_parity"):
            self.assertNotIn(
                banned, doc,
                "per-check outcomes are machine-dependent and must stay in "
                "the git-ignored snapshot")

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


class TestQuarantineCountIsLive(unittest.TestCase):
    def test_readme_quotes_splits_v2_quarantine_row_count(self):
        n = sum(1 for line in (ROOT / "splits_v2" / "quarantine.jsonl")
                .read_text(encoding="utf-8").splitlines() if line.strip())
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn(f"{n}-row `splits_v2/quarantine.jsonl`", readme)
        self.assertNotIn("63-row `splits_v2/quarantine.jsonl`", readme)
        vb = sum(1 for line in (
            ROOT / "Vbeta" / "splits_vbeta" / "quarantine.jsonl")
            .read_text(encoding="utf-8").splitlines() if line.strip())
        self.assertIn(f"{vb}-row file is `Vbeta/splits_vbeta/quarantine.jsonl`",
                      readme)


if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(ROOT / "scripts"))
    unittest.main(verbosity=2)