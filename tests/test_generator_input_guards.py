"""Per-script write-path guards: a generator that cannot see its inputs must not
overwrite the layer those inputs produced.

The regression this tests (2026-11-04, found by audit): a full regeneration
cascade ran on a checkout holding NONE of the git-ignored inputs. Three
generators recomputed from what they could read and published the smaller truth
over the committed one — `derived_prove/candidate_ledger.jsonl` 210 -> 38 rows
(172 candidate ids gone with their licence/poc/rights/blocker fields),
`reports/citation_resolution.json` 473 pinned citations -> none,
`reports/counterexample_stats.json` 99 -> 12 counterexamples and 71 -> 0
API-sibling pairs, which README then asserted in prose. `build_all.py` now
restores those paths, but running a script directly bypassed everything — so
each script guards its own write path.

Each guard is tested both ways, because the two trips are independent failures:

  * the input the published output was built from is NOT on disk, and
  * the input IS on disk but the recomputed total is below the published floor
    (a count that only moves downward when nothing was added is not a
    measurement, so the committed totals are the floor).

For each: the run reports a refusal naming the missing path and what it would
have destroyed, the pre-existing published bytes survive UNCHANGED (the crux —
a guard that logs a warning and writes anyway is the failure mode), and
`--allow-shrink` does write.
"""
from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import build_all as BA  # noqa: E402
import build_counterexamples as ce  # noqa: E402
import build_prove_ledger as bl  # noqa: E402
import resolve_citations as rc  # noqa: E402

# The five paths the audit restored from the parent commit and added to
# CANONICAL_LAYERS. They are listed here by name so a silent removal fails.
RESTORED_PATHS = (
    "derived_prove/candidate_ledger.jsonl",
    "reports/citation_resolution.json",
    "reports/counterexample_stats.json",
    "reports/prove_candidate_ledger.json",
    "reports/prove_candidate_ledger.md",
)


def call(main_fn, argv=(), takes_argv=False):
    """Run a script's main() in-process, capturing its report, returning (rc, log)."""
    buf = io.StringIO()
    if takes_argv:
        with contextlib.redirect_stdout(buf):
            code = main_fn(list(argv))
    else:
        with mock.patch.object(sys, "argv", ["scripts/script.py", *argv]), \
                contextlib.redirect_stdout(buf):
            code = main_fn()
    return code, buf.getvalue()


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n"
                            for r in rows), encoding="utf-8", newline="\n")


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
                    encoding="utf-8", newline="\n")


class CanonicalLayerRestoreTest(unittest.TestCase):
    def test_the_five_restored_paths_are_canonical_layers(self):
        for rel in RESTORED_PATHS:
            self.assertIn(rel, BA.CANONICAL_LAYERS,
                          f"{rel} is not guarded by build_all: a whole-tree rebuild "
                          "would rewrite it again")


class ProveLedgerGuardTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.root = root
        self.cand = root / "work" / "prove_candidates"          # deliberately absent
        self.ledger = root / "derived_prove" / "candidate_ledger.jsonl"
        self.stats_json = root / "reports" / "prove_candidate_ledger.json"
        self.stats_md = root / "reports" / "prove_candidate_ledger.md"
        self.published_rows = [
            {"candidate_id": "discovered::a", "candidate_stage": "candidate",
             "repository": "repo-one", "licence_code": "MIT (MIT)",
             "rights_status": "cleared_for_redistribution"},
            {"candidate_id": "discovered::b", "candidate_stage": "candidate",
             "repository": "repo-two", "licence_code": "BUSL-1.1",
             "blocker": "no fixture at the pinned revision"},
            {"candidate_id": "discovered::c", "candidate_stage": "candidate",
             "repository": "repo-two", "licence_code": "MIT (MIT)"},
        ]
        write_jsonl(self.ledger, self.published_rows)
        write_json(self.stats_json, {
            "input_ledgers": ["local_ledger.jsonl:3"],
            "counts": {"candidate_rows": 3, "distinct_repositories": 2,
                       "distinct_repositories_with_a_qualified_task": 0,
                       "by_stage": {"candidate": 3}, "by_licence": {"MIT": 2, "BUSL-1.1": 1}},
        })
        self.stats_md.write_text("# published\n", encoding="utf-8", newline="\n")
        self.snapshot = {p: p.read_bytes()
                         for p in (self.ledger, self.stats_json, self.stats_md)}
        self.patches = mock.patch.multiple(
            bl, ROOT=root, REPORTS=root / "reports", CANDIDATE_DIR=self.cand,
            OUT_DIR=root / "derived_prove", LEDGER=self.ledger,
            STATS_JSON=self.stats_json, STATS_MD=self.stats_md)
        self.patches.start()
        self.addCleanup(self.patches.stop)

    def _restore_untouched(self):
        for path, blob in self.snapshot.items():
            self.assertEqual(path.read_bytes(), blob,
                             f"{path.name} was written despite the refusal")

    def test_absent_input_ledger_refuses_the_write(self):
        code, out = call(bl.main)
        self.assertEqual(code, 1, out)
        self.assertIn("REFUSED", out)
        self.assertIn("work/prove_candidates", out)
        # names what it would have destroyed, in numbers, not adjectives
        self.assertIn("3 of 3 published candidate ids", out)
        self.assertIn("licence_code", out)
        self.assertIn("3 -> 0", out)
        self._restore_untouched()

    def test_published_floor_refuses_even_when_the_input_dir_is_present(self):
        """The count floor, independent of the missing-directory precondition."""
        write_jsonl(self.cand / "local_ledger.jsonl", self.published_rows[:2])
        code, out = call(bl.main)
        self.assertEqual(code, 1, out)
        self.assertIn("REFUSED", out)
        self.assertIn("discovered::c", out)
        self.assertIn("3 -> 2", out)
        self._restore_untouched()

    def test_allow_shrink_is_the_escape_hatch_and_does_write(self):
        write_jsonl(self.cand / "local_ledger.jsonl", self.published_rows[:2])
        code, out = call(bl.main, ["--allow-shrink"])
        self.assertNotIn("REFUSED", out)
        self.assertIn("--allow-shrink was given", out)
        rows = bl._load(self.ledger)
        self.assertEqual(sorted(r["candidate_id"] for r in rows),
                         ["discovered::a", "discovered::b"])
        self.assertNotEqual(self.stats_json.read_bytes(), self.snapshot[self.stats_json])


class CitationResolutionGuardTest(unittest.TestCase):
    URL_ONE = "https://github.com/some-org/some-repo/blob/main/src/A.sol"
    URL_TWO = "https://github.com/other-org/other-repo/blob/master/src/B.sol"
    PIN_ONE = "1111111111111111111111111111111111111111"
    PIN_TWO = "2222222222222222222222222222222222222222"

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.work = root / "work"                     # deliberately absent: no clones
        self.records = root / "derived" / "records.jsonl"
        self.out = root / "reports" / "citation_resolution.json"
        write_jsonl(self.records, [
            {"id": "2024-01-audit/H-1",
             "source": {"repository": "some-repo", "audit_date": "2024-01-15"},
             "code_context": [{"file": "src/A.sol", "source_url": self.URL_ONE,
                               "line_start": 1, "line_end": 4}]},
            {"id": "2024-01-audit/M-2",
             "source": {"repository": "other-repo", "audit_date": "2024-02-02"},
             "code_context": [{"file": "src/B.sol", "source_url": self.URL_TWO,
                               "line_start": 9, "line_end": 20}]},
        ])
        write_json(self.out, {
            "by_status": {"resolved": 2},
            "applied": {"citations_pinned": 2, "citations_seen": 2},
            "citations": [
                {"record_id": "2024-01-audit/H-1", "context_key": "code_context",
                 "source_url_original": self.URL_ONE, "resolved_commit": self.PIN_ONE},
                {"record_id": "2024-01-audit/M-2", "context_key": "code_context",
                 "source_url_original": self.URL_TWO, "resolved_commit": self.PIN_TWO},
            ],
        })
        self.snapshot = {p: p.read_bytes() for p in (self.out, self.records)}
        self.patches = mock.patch.multiple(
            rc, WORK=self.work, DERIVED=root / "derived", REPORTS=root / "reports")
        self.patches.start()
        self.addCleanup(self.patches.stop)
        self.addCleanup(self._clear_caches)
        self._clear_caches()

    def _clear_caches(self):
        for value in vars(rc).values():
            if hasattr(value, "cache_clear"):
                value.cache_clear()

    def _argv(self, *extra):
        return ["--records", str(self.records), "--out", str(self.out), *extra]

    def test_no_visible_clone_refuses_and_keeps_the_pins(self):
        code, out = call(rc.main, self._argv())
        self.assertEqual(code, 1, out)
        self.assertIn("REFUSED", out)
        self.assertIn("work/wt", out)
        self.assertIn("work/source_manifest.json", out)
        self.assertIn("2 of 2 published pinned citations", out)
        self.assertIn("resolved_commit", out)
        for path, blob in self.snapshot.items():
            self.assertEqual(path.read_bytes(), blob,
                             f"{path.name} was written despite the refusal")

    def test_partial_input_still_hits_the_pin_floor(self):
        """A clone tree that exists but holds none of the cited repos."""
        (self.work / "wt" / "renft-smart" / ".git").mkdir(parents=True)
        code, out = call(rc.main, self._argv())
        self.assertEqual(code, 1, out)
        self.assertIn("REFUSED", out)
        self.assertIn("2 of 2 published pinned citations", out)
        self.assertEqual(self.out.read_bytes(), self.snapshot[self.out])

    def test_allow_shrink_is_the_escape_hatch_and_does_write(self):
        code, out = call(rc.main, self._argv("--allow-shrink"))
        self.assertNotIn("REFUSED", out)
        self.assertEqual(code, 0, out)
        self.assertNotEqual(self.out.read_bytes(), self.snapshot[self.out])
        doc = json.loads(self.out.read_text(encoding="utf-8"))
        self.assertEqual(len(doc["citations"]), 2)
        self.assertFalse([c for c in doc["citations"] if c["resolved_commit"]])


class CounterexamplesGuardTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.work = root / "work"
        self.jsonl = root / "jsonl"
        self.derived = root / "derived"
        self.reports = root / "reports"
        self.stats_json = self.reports / "counterexample_stats.json"
        self.layer = self.derived / "counterexamples.jsonl"
        write_jsonl(self.jsonl / "findings.jsonl", [
            {"dataset_version": "2.2",
             "source": {"organization": "code-423n4", "repository": "some-repo"},
             "finding": {"id": "2024-01-audit/H-1", "record_class": "judged",
                         "severity": "high", "title": "unchecked withdrawal",
                         "affected_functions": ["Vault.withdraw"],
                         "vulnerability_classes": ["reentrancy"]},
             "code_context": [{"file": "src/Vault.sol", "function": "viewBalance",
                               "commit_sha": "3333333333333333333333333333333333333333",
                               "source_url": "https://github.com/code-423n4/some-repo/"
                                             "blob/main/src/Vault.sol",
                               "line_start": 1, "line_end": 12,
                               "snippet": (
                                   "contract Vault {\n"
                                   "  mapping(address => uint256) public balances;\n"
                                   "  function withdraw() external onlyOwner {}\n"
                                   "  function viewBalance() external view "
                                   "returns (uint256) { return 0; }\n"
                                   "}\n")}]},
        ])
        write_jsonl(self.layer, [{"record_type": "counterexample_set",
                                  "finding_id": f"f{i}", "counterexamples": [],
                                  "api_sibling_pairs": [{"type": "guard_missing"}]}
                                 for i in range(63)])
        write_json(self.stats_json, {
            "confirmed_high_medium_records": 204,
            "records_with_at_least_one_counterexample": 43,
            "total_counterexamples": 99,
            "by_type": {"access_control_refutation": 30, "mutability_refutation": 69},
            "api_sibling_pairs": 71,
            "records_with_api_sibling_pairs": 30,
            "api_sibling_pair_types": {"guard_missing": 71},
        })
        self.snapshot = {p: p.read_bytes() for p in (self.stats_json, self.layer)}
        self.patches = mock.patch.multiple(
            ce, WORK=self.work, JSONL=self.jsonl, DERIVED=self.derived,
            REPORTS=self.reports, STATS_JSON=self.stats_json, LAYER_JSONL=self.layer)
        self.patches.start()
        self.addCleanup(self.patches.stop)
        # The retrieved-source reader is stubbed: this test is about the write-path
        # guard, and it must not depend on what happens to be under the real work/.
        stub = types.ModuleType("local_sources")
        stub.analyse_cited = lambda owner, entry, allow_text: {
            "file": entry.get("file"), "commit_sha": entry.get("commit_sha"),
            "source_url": entry.get("source_url"), "retrieved_locally": False,
            "functions": [], "contracts": []}
        self.modules = mock.patch.dict(sys.modules, {"local_sources": stub})
        self.modules.start()
        self.addCleanup(self.modules.stop)

    def test_absent_retrieved_source_refuses_and_keeps_the_published_files(self):
        code, out = call(ce.main)
        self.assertEqual(code, 1, out)
        self.assertIn("REFUSED", out)
        self.assertIn("work/source_manifest.json", out)
        self.assertIn("work/repos", out)
        self.assertIn("total_counterexamples 99 -> ", out)
        self.assertIn("api_sibling_pairs 71 -> ", out)
        self.assertIn("63 published records", out)
        for path, blob in self.snapshot.items():
            self.assertEqual(path.read_bytes(), blob,
                             f"{path.name} was written despite the refusal")

    def test_input_present_but_counts_shrunk_still_refuses(self):
        """The floor alone: an empty-but-existing work/ tree satisfies the precondition."""
        for name in ("source_manifest.json",):
            (self.work / name).parent.mkdir(parents=True, exist_ok=True)
            (self.work / name).write_text("{\"repos\": []}\n", encoding="utf-8")
        (self.work / "sources").mkdir(parents=True, exist_ok=True)
        (self.work / "repos").mkdir(parents=True, exist_ok=True)
        code, out = call(ce.main)
        self.assertEqual(code, 1, out)
        self.assertIn("REFUSED", out)
        self.assertNotIn("none of the retrieved-source inputs", out)
        self.assertIn("api_sibling_pair_types guard_missing 71 -> 0", out)
        self.assertEqual(self.stats_json.read_bytes(), self.snapshot[self.stats_json])
        self.assertEqual(self.layer.read_bytes(), self.snapshot[self.layer])

    def test_allow_shrink_is_the_escape_hatch_and_does_write(self):
        code, out = call(ce.main, ["--allow-shrink"])
        self.assertNotIn("REFUSED", out)
        self.assertIn("--allow-shrink was given", out)
        self.assertEqual(code, 0, out)
        self.assertNotEqual(self.stats_json.read_bytes(), self.snapshot[self.stats_json])
        stats = json.loads(self.stats_json.read_text(encoding="utf-8"))
        self.assertLess(stats["total_counterexamples"], 99)
        self.assertEqual(stats["api_sibling_pairs"], 0)
        rows = [json.loads(line) for line in
                self.layer.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertLess(len(rows), 63)


if __name__ == "__main__":
    unittest.main(verbosity=2)
