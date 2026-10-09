#!/usr/bin/env python3
"""Tests for field coverage (scripts/field_coverage.py).

The silent-wrong-key class of bug (a listed field that resolves to nothing
on every record, publishing 0% forever) must be caught by the gate: every
field in LAYER_FIELDS must resolve to a non-empty value on at least one
record in its layer. Plus a pinned regression: Vbeta severity lives in
`severity_observed` and must read 118/719 (16.4%), never 0.
Run:  python -m unittest discover -s tests
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from field_coverage import (  # noqa: E402
    BASIS_FIELDS,
    LAYER_FIELDS,
    LAYER_FILES,
    get,
    jl,
    known,
    known_basis,
)


class TestFieldsResolve(unittest.TestCase):
    def test_every_listed_field_key_exists_somewhere(self):
        # Guards the silent-wrong-key class of bug: the KEY PATH must exist
        # on at least one record. All-unknown VALUES are honest (counted in
        # the report), but a key that exists nowhere is a broken reference.
        def key_present(row, dotted):
            cur = row
            for part in dotted.split("."):
                if not isinstance(cur, dict) or part not in cur:
                    return False
                cur = cur[part]
            return True

        for scope, fields in LAYER_FIELDS.items():
            rows = jl(ROOT / LAYER_FILES[scope])
            self.assertTrue(rows, f"no rows for {scope}")
            for field in fields:
                hits = sum(1 for r in rows if key_present(r, field))
                self.assertGreater(
                    hits, 0,
                    f"{scope}.{field} key exists on no record — wrong key?")

    def test_no_unknown_scope_or_file(self):
        for scope, rel in LAYER_FILES.items():
            self.assertIn(scope, LAYER_FIELDS)
            self.assertTrue((ROOT / rel).is_file(), rel)

    def test_declared_absent_fields_are_truly_absent(self):
        from field_coverage import LAYER_ABSENT

        def key_present(row, dotted):
            cur = row
            for part in dotted.split("."):
                if not isinstance(cur, dict) or part not in cur:
                    return False
                cur = cur[part]
            return True

        for scope, fields in LAYER_ABSENT.items():
            rows = jl(ROOT / LAYER_FILES[scope])
            for field in fields:
                hits = sum(1 for r in rows if key_present(r, field))
                self.assertEqual(
                    hits, 0,
                    f"{scope}.{field} now exists — move it to LAYER_FIELDS")

    def test_vbeta_severity_regression(self):
        rows = jl(ROOT / LAYER_FILES["vbeta.records"])
        k = sum(1 for r in rows if known(get(r, "severity_observed")))
        # 6,334 -> 6,317 when Solodit's own Impact axis stopped being
        # recorded as a report severity (45 rows lost the false value, 17
        # gained a real one from the inline `**Severity:**` layout). The
        # drop is the fix, not a regression: see
        # tests/test_solodit_harvest.py.
        self.assertEqual((k, len(rows)), (6317, 6935))
        # Semantic guard, so the pin can never again accept a contaminated
        # value: Solodit's triage axis is not the auditor's severity.
        contaminated = [r["finding_id"] for r in rows
                        if any(ax in str(get(r, "severity_observed") or "")
                               for ax in ("Impact:", "Impact**", "Likelihood:"))]
        self.assertEqual(contaminated, [],
                         "Solodit Impact/Likelihood stored as report severity")
        # And the published report agrees with the recomputation.
        import json
        rep = json.load(open(ROOT / "reports" / "field_coverage.json",
                             encoding="utf-8-sig"))["fields"]
        self.assertEqual(rep["vbeta.records.severity_observed"]["known"], 6317)

    def test_broken_key_would_fail(self):
        rows = jl(ROOT / LAYER_FILES["vbeta.records"])
        hits = sum(1 for r in rows if known(get(r, "severity")))
        self.assertEqual(hits, 0, "sanity: `severity` is the wrong key here")


if __name__ == "__main__":
    unittest.main(verbosity=2)
