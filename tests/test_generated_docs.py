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
    return [json.loads(l) for l in p.open(encoding="utf-8") if l.strip()]


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
        rc = json.loads((ROOT / "reports" / "reproducibility_checks.json")
                        .read_text(encoding="utf-8"))
        self.assertIn(f"{mc['checks_total']}", text)
        self.assertIn(f"{rc['checks_total']}", text)
        self.assertNotIn("119 count/reference checks", text)
        self.assertNotIn("16 provenance/determinism checks", text)


if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(ROOT / "scripts"))
    unittest.main(verbosity=2)