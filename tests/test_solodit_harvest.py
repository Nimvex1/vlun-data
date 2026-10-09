"""Solodit harvester: both corpus layouts, and severity vs Impact.

The scraped corpus carries two shapes for the same logical field:

  structured   '## Severity\\n\\nHigh Risk'
  inline       '**Status:** Complete'

The old section() only matched the first, so inline labels were invisible.
Worse, Solodit renders its own triage widget ('**Impact:** Low /
'**Likelihood:** High') under the '## Severity' heading, so 45 harvested rows
stored Solodit's filtered impact as if the auditor had stated a severity.
Both are pinned here.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "Vbeta" / "scripts"))

import harvest_solodit as H  # noqa: E402


class TestLayouts(unittest.TestCase):
    STRUCTURED = (
        "# Title here\n\n## Severity\n\nHigh Risk\n\n"
        "## Description\n\nThe queue can be drained by anyone at all.\n\n"
        "## Recommendation\n\nRestrict the caller.\n\n## Team Response\n\nFixed.\n"
    )
    INLINE = (
        "# Title here\n\n**Severity:** High Risk\n\n"
        "**Description:** The queue can be drained by anyone at all.\n\n"
        "**Recommendation:** Restrict the caller.\n\n"
        "**Status:** Complete\n"
    )
    SIDEBAR = (
        "# Title here\n\n## Severity\n\n**Impact:** Low\n\n**Likelihood:** High\n\n"
        "## Description\n\nPrice maths disagree across feeds.\n\n"
        "**Status:** Acknowledged\n"
    )

    def test_structured_heading_layout(self):
        self.assertEqual(H.section(self.STRUCTURED, "Severity"), "High Risk")
        self.assertIn("drained", H.section(self.STRUCTURED, "Description"))
        sev, _ = H.report_severity(self.STRUCTURED)
        self.assertEqual(sev, "High Risk")

    def test_inline_label_layout(self):
        self.assertEqual(H.section(self.INLINE, "Severity"), "",
                         "a bold label is not a heading")
        self.assertEqual(H.inline_label(self.INLINE, "Status"), "Complete")
        self.assertEqual(H.inline_label(self.INLINE, "Severity"), "High Risk")
        sev, _ = H.report_severity(self.INLINE)
        self.assertEqual(sev, "High Risk")

    def test_section_or_label_reads_both(self):
        for text in (self.STRUCTURED, self.INLINE):
            self.assertIn("Restrict", H.section_or_label(text, "Recommendation"))
            self.assertIn("drained", H.section_or_label(text, "Description"))

    def test_status_reads_team_response_or_inline_status(self):
        # '## Team Response' (structured) and '**Status:**' (inline) are
        # the same logical field in the two corpus layouts.
        self.assertEqual(
            H.clean_md(H.section_or_label(self.STRUCTURED, "Team Response")
                       .split("\n")[0])[:60], "Fixed.")
        self.assertEqual(
            H.clean_md(H.section_or_label(self.INLINE, "Status")
                       .split("\n")[0])[:60], "Complete")


class TestSeverityIsNotSoloditImpact(unittest.TestCase):
    SIDEBAR_ONLY = (
        "# Title\n\n## Severity\n\n**Impact:** Low\n\n**Likelihood:** High\n\n"
        "## Description\n\nSomething.\n"
    )

    def test_widget_is_not_report_severity(self):
        sev, sidebar = H.report_severity(self.SIDEBAR_ONLY)
        self.assertIsNone(sev,
                          "Solodit's Impact axis must never become the "
                          "report's severity")
        self.assertEqual(sidebar.get("impact"), "Low")
        self.assertEqual(sidebar.get("likelihood"), "High")

    def test_widget_stripped_before_reading(self):
        body = H.strip_solodit_axes(H.section(self.SIDEBAR_ONLY, "Severity"))
        self.assertNotIn("Impact", body)
        self.assertNotIn("Likelihood", body)

    def test_report_severity_survives_a_widget_sibling(self):
        text = ("# Title\n\n## Severity\n\nCritical Risk\n\n"
                "**Impact:** High\n\n**Likelihood:** Medium\n")
        sev, sidebar = H.report_severity(text)
        self.assertEqual(sev, "Critical Risk")
        self.assertEqual(sidebar.get("impact"), "High")


class TestNoSeverityInferredFromFilter(unittest.TestCase):
    def test_harvested_corpus_separates_report_severity_from_impact(self):
        p = ROOT / "Vbeta" / "solodit_candidates.json"
        if not p.is_file():
            self.skipTest("solodit_candidates.json absent (scrape not run)")
        rows = json.loads(p.read_text(encoding="utf-8"))
        for r in rows:
            sev = str(r.get("severity_observed") or "")
            self.assertNotIn("Impact", sev,
                             f"{r['cid']}: Solodit Impact stored as severity")
            self.assertNotIn("Likelihood", sev, r["cid"])

    def test_every_row_states_its_severity_provenance(self):
        p = ROOT / "Vbeta" / "solodit_candidates.json"
        if not p.is_file():
            self.skipTest("solodit_candidates.json absent")
        for r in json.loads(p.read_text(encoding="utf-8")):
            self.assertIn("severity_evidence", r, r["cid"])


if __name__ == "__main__":
    unittest.main(verbosity=2)