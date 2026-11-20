"""Clean-checkout behaviour of the prove-ledger ``--check`` gate.

A fresh public checkout has no git-ignored ``work/prove_candidates/`` ledgers, so
the committed ledger cannot be re-derived. In that case ``--check`` must VERIFY
the published ledger + stats honestly and log ``skipped_no_private_inputs``
(exit 0); if those committed artefacts are corrupt it must fail (exit 1), never
silently pass. Every path in this module points at a temporary directory, so the
real repository is never read from or written to.
"""
from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import build_prove_ledger as bl  # noqa: E402


VALID_ROW = {
    "candidate_id": "fixture::1",
    "candidate_stage": "candidate",
    "repository": "https://github.com/example/repo.git",
}


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows),
                    encoding="utf-8", newline="\n")


def _write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8", newline="\n")


def _stats_for(rows: list[dict]) -> dict:
    """A stats document consistent with ``rows`` (mirrors summarise()'s keys)."""
    by_stage: dict[str, int] = {}
    for row in rows:
        stage = row["candidate_stage"]
        by_stage[stage] = by_stage.get(stage, 0) + 1
    repos = {r["repository"] for r in rows if r.get("repository")}
    return {
        "schema_version": bl.SCHEMA_VERSION,
        "generated_by": "scripts/build_prove_ledger.py",
        "counts": {
            "candidate_rows": len(rows),
            "by_stage": by_stage,
            "distinct_repositories": len(repos),
            "distinct_repositories_with_a_qualified_task": 0,
            "by_framework": {"unknown": len(rows)},
            "by_origin": {"fixture": len(rows)},
        },
    }


class CleanCheckoutIntegrityTest(unittest.TestCase):
    """The pure helper, exercised against a temp tree with no monkeypatching."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.ledger = self.root / "derived_prove" / "candidate_ledger.jsonl"
        self.stats = self.root / "reports" / "prove_candidate_ledger.json"
        _write_jsonl(self.ledger, [dict(VALID_ROW)])
        _write_json(self.stats, _stats_for([dict(VALID_ROW)]))
        self._snapshot()

    def _snapshot(self):
        self.snapshot = {p: p.read_bytes() for p in (self.ledger, self.stats)
                         if p.exists()}

    def _assert_untouched(self):
        for path, blob in self.snapshot.items():
            self.assertEqual(path.read_bytes(), blob,
                             f"{path.name} was rewritten by the integrity check")

    # (a) a valid committed ledger + stats yields the skip verdict.
    def test_valid_committed_artefacts_yield_the_skip_token(self):
        ok, message = bl.check_committed_ledger_integrity(self.root)
        self.assertTrue(ok, message)
        self.assertIn("skipped_no_private_inputs", message)
        self.assertIn("1 rows", message)  # reason AND row count are logged
        self._assert_untouched()

    # (b) corruption yields a failure verdict, never a silent pass.
    def test_duplicate_id_fails(self):
        _write_jsonl(self.ledger, [dict(VALID_ROW), dict(VALID_ROW)])
        self._snapshot()
        ok, message = bl.check_committed_ledger_integrity(self.root)
        self.assertFalse(ok)
        self.assertIn("duplicate", message.lower())
        self.assertNotIn("skipped_no_private_inputs", message)
        self._assert_untouched()

    def test_bad_stage_fails(self):
        _write_jsonl(self.ledger, [dict(VALID_ROW, candidate_stage="almost_qualified")])
        self._snapshot()
        ok, message = bl.check_committed_ledger_integrity(self.root)
        self.assertFalse(ok)
        self.assertIn("candidate_stage", message)
        self.assertNotIn("skipped_no_private_inputs", message)
        self._assert_untouched()

    def test_missing_stats_fails(self):
        self.stats.unlink()
        self._snapshot()
        ok, message = bl.check_committed_ledger_integrity(self.root)
        self.assertFalse(ok)
        self.assertIn("prove_candidate_ledger.json", message)
        self.assertIn("missing", message)
        self.assertNotIn("skipped_no_private_inputs", message)
        self._assert_untouched()

    def test_missing_qualification_fields_fail(self):
        _write_jsonl(self.ledger, [dict(VALID_ROW, candidate_stage="qualified")])
        self._snapshot()
        ok, message = bl.check_committed_ledger_integrity(self.root)
        self.assertFalse(ok)
        self.assertIn("qualified", message)
        self.assertNotIn("skipped_no_private_inputs", message)
        self._assert_untouched()

    def test_row_count_mismatch_fails(self):
        _write_json(self.stats, _stats_for([dict(VALID_ROW), dict(VALID_ROW)]))
        self._snapshot()
        ok, message = bl.check_committed_ledger_integrity(self.root)
        self.assertFalse(ok)
        self.assertIn("candidate_rows", message)
        self.assertNotIn("skipped_no_private_inputs", message)
        self._assert_untouched()


class CleanCheckoutGateTest(unittest.TestCase):
    """``main() --check`` wiring: module paths are monkeypatched to a temp tree
    and restored in tearDown, so no real repository path is touched."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.ledger = root / "derived_prove" / "candidate_ledger.jsonl"
        self.stats = root / "reports" / "prove_candidate_ledger.json"
        _write_jsonl(self.ledger, [dict(VALID_ROW)])
        _write_json(self.stats, _stats_for([dict(VALID_ROW)]))
        self.patches = mock.patch.multiple(
            bl, ROOT=root, REPORTS=root / "reports",
            CANDIDATE_DIR=root / "work" / "prove_candidates",  # deliberately absent
            OUT_DIR=root / "derived_prove", LEDGER=self.ledger,
            STATS_JSON=self.stats,
            STATS_MD=root / "reports" / "prove_candidate_ledger.md")
        self.patches.start()

    def tearDown(self):
        self.patches.stop()

    def _run_check(self):
        buf = io.StringIO()
        with mock.patch.object(sys, "argv",
                               ["scripts/build_prove_ledger.py", "--check"]), \
                contextlib.redirect_stdout(buf):
            code = bl.main()
        return code, buf.getvalue()

    def test_check_skips_with_the_token_and_exits_zero(self):
        code, out = self._run_check()
        self.assertEqual(code, 0, out)
        self.assertIn("skipped_no_private_inputs", out)

    def test_check_fails_on_corrupt_committed_ledger(self):
        _write_jsonl(self.ledger, [dict(VALID_ROW), dict(VALID_ROW)])
        code, out = self._run_check()
        self.assertEqual(code, 1, out)
        self.assertIn("committed ledger integrity failed", out)
        self.assertNotIn("skipped_no_private_inputs", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
