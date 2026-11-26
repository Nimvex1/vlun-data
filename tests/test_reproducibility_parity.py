#!/usr/bin/env python3
"""The rebuild-parity helper must be able to fail.

The v2.1 audit's REFUTED-2 was a rebuild gate whose "outputs differ" branch
was dead code: the snapshot of the rebuild's own output was taken AFTER the
`finally` block had restored the committed bytes, so `before != after` could
never be true and the gate could only ever detect a builder that crashed.
A green gate that cannot go red is not a gate.

These tests pin the properties that make the branch alive:
  * a replay whose output differs from the committed bytes FAILS, and the
    failure names the exact residual difference;
  * the committed bytes are restored afterwards, so the check observes and
    never leaves a degraded layer behind;
  * a replay that crashes FAILS (rc is reported, the step is named);
  * missing citation inputs SKIP with `skipped_no_network`, which is visibly
    not a pass;
  * the derived/ chain replays the DOCUMENTED pipeline (build_derived ->
    the authoritative citation-pin replay -> the record-hash migration),
    not one stage. The citation stage is `replay_v1_citation_pins.py`, not
    `resolve_citations.py`: the latter's git-ignored clones are absent in a
    partial checkout, so its own write-guard refuses to run; see the test below.

Run:  python -m unittest tests.test_reproducibility_parity -v
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "Vbeta" / "scripts"))

from check_reproducibility import (  # noqa: E402
    DERIVED_CHAIN,
    DERIVED_FILES,
    VBETA_CHAIN,
    VBETA_FILES,
    Gate,
    rebuild_parity,
    residual_summary,
)
import build_vbeta as B  # noqa: E402

COMMITTED = b'{"id": "r1", "value": "committed"}\n'


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


class ParityHarness(unittest.TestCase):
    """A temp root with a committed layer and one or more builder scripts."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.layer = self.root / "layer" / "records.jsonl"
        _write(self.layer, COMMITTED.decode("utf-8"))
        self.gate = Gate(quiet=True)

    def tearDown(self):
        self._tmp.cleanup()

    def builder(self, name: str, body: str) -> str:
        _write(self.root / name, body)
        return name

    def status(self) -> str:
        self.assertTrue(self.gate.rows, "the gate recorded no verdict")
        return self.gate.rows[-1]["status"]

    def detail(self) -> str:
        return self.gate.rows[-1]["detail"]


class TestParityDetectsDrift(ParityHarness):
    def test_injected_byte_difference_is_detected(self):
        """A builder that changes one byte must make the gate FAIL."""
        self.builder("drift.py",
                     "from pathlib import Path\n"
                     "p = Path('layer/records.jsonl')\n"
                     "p.write_bytes(p.read_bytes().replace(b'committed', b'drifted'))\n")
        result = rebuild_parity(self.gate, "layer/", [("drift.py", [])],
                                ["layer/records.jsonl"], [], root=self.root)
        self.assertEqual(self.status(), "FAIL")
        self.assertEqual(result["status"], "differs")
        self.assertIn("layer/records.jsonl", result["changed"])

    def test_the_residual_difference_is_named(self):
        self.builder("drift.py",
                     "from pathlib import Path\n"
                     "import json\n"
                     "p = Path('layer/records.jsonl')\n"
                     "rec = json.loads(p.read_text(encoding='utf-8'))\n"
                     "rec['value'] = 'drifted'\n"
                     "p.write_text(json.dumps(rec, sort_keys=True) + '\\n', encoding='utf-8')\n")
        rebuild_parity(self.gate, "layer/", [("drift.py", [])],
                       ["layer/records.jsonl"], [], root=self.root)
        self.assertEqual(self.status(), "FAIL")
        # The failure names the field that drifted, not just "outputs differ".
        self.assertIn("value", self.detail())
        self.assertIn("records differ", self.detail())

    def test_identical_rebuild_passes(self):
        """The negative control: the same bytes must still be a pass."""
        self.builder("same.py",
                     "from pathlib import Path\n"
                     "p = Path('layer/records.jsonl')\n"
                     "p.write_bytes(p.read_bytes())\n")
        result = rebuild_parity(self.gate, "layer/", [("same.py", [])],
                                ["layer/records.jsonl"], [], root=self.root)
        self.assertEqual(self.status(), "PASS")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["changed"], [])

    def test_committed_bytes_are_restored_after_a_drift(self):
        """The check observes; it must never leave a degraded layer behind."""
        self.builder("drift.py",
                     "from pathlib import Path\n"
                     "p = Path('layer/records.jsonl')\n"
                     "p.write_bytes(b'{\"id\": \"r1\", \"value\": \"drifted\"}\\n')\n")
        rebuild_parity(self.gate, "layer/", [("drift.py", [])],
                       ["layer/records.jsonl"], [], root=self.root)
        self.assertEqual(self.layer.read_bytes(), COMMITTED)

    def test_a_crashing_builder_is_reported_with_its_step(self):
        self.builder("boom.py", "import sys\nsys.exit(3)\n")
        result = rebuild_parity(self.gate, "layer/", [("boom.py", [])],
                                ["layer/records.jsonl"], [], root=self.root)
        self.assertEqual(self.status(), "FAIL")
        self.assertEqual(result["status"], "failed")
        self.assertIn("rc=3", self.detail())
        self.assertIn("boom.py", self.detail())
        self.assertEqual(self.layer.read_bytes(), COMMITTED)

    def test_a_stray_tmp_file_is_not_left_behind(self):
        self.builder("boom.py",
                     "from pathlib import Path\n"
                     "Path('layer/records.jsonl.tmp').write_bytes(b'x')\n"
                     "raise SystemExit(1)\n")
        rebuild_parity(self.gate, "layer/", [("boom.py", [])],
                       ["layer/records.jsonl"], [], root=self.root)
        self.assertFalse((self.root / "layer" / "records.jsonl.tmp").exists())
        self.assertEqual(self.layer.read_bytes(), COMMITTED)

    def test_the_chain_runs_in_order(self):
        """Step 2 sees step 1's output: the chain is a pipeline, not a set."""
        self.builder("step1.py",
                     "from pathlib import Path\n"
                     "Path('layer/records.jsonl').write_bytes(b'{\"id\": \"r1\", \"value\": \"one\"}\\n')\n")
        self.builder("step2.py",
                     "from pathlib import Path\n"
                     "p = Path('layer/records.jsonl')\n"
                     "assert b'one' in p.read_bytes(), 'step 2 did not see step 1'\n"
                     "p.write_bytes(b'{\"id\": \"r1\", \"value\": \"two\"}\\n')\n")
        rebuild_parity(self.gate, "layer/",
                       [("step1.py", []), ("step2.py", [])],
                       ["layer/records.jsonl"], [], root=self.root)
        self.assertEqual(self.status(), "FAIL")
        self.assertEqual(self.layer.read_bytes(), COMMITTED)

    def test_a_failing_step_stops_the_chain(self):
        self.builder("step1.py",
                     "from pathlib import Path\n"
                     "Path('layer/records.jsonl').write_bytes(b'{\"id\": \"r1\", \"value\": \"one\"}\\n')\n")
        self.builder("step2.py", "raise SystemExit(1)\n")
        self.builder("step3.py",
                     "from pathlib import Path\n"
                     "Path('layer/step3_ran').write_bytes(b'x')\n")
        rebuild_parity(self.gate, "layer/",
                       [("step1.py", []), ("step2.py", []), ("step3.py", [])],
                       ["layer/records.jsonl"], [], root=self.root)
        self.assertEqual(self.status(), "FAIL")
        # step 3 must never run: the chain stops at the first failure.
        self.assertFalse((self.root / "layer" / "step3_ran").exists())
        self.assertEqual(self.layer.read_bytes(), COMMITTED)


class TestParitySkipSemantics(ParityHarness):
    def test_missing_inputs_skip_and_are_not_a_pass(self):
        result = rebuild_parity(self.gate, "layer/", [("drift.py", [])],
                                ["layer/records.jsonl"],
                                ["work/source_manifest.json"], root=self.root)
        self.assertEqual(self.status(), "SKIPPED")
        self.assertNotEqual(self.status(), "PASS")
        self.assertIn("skipped_no_network", self.detail())
        self.assertEqual(result["status"], "skipped")
        # a skip must not touch the layer either
        self.assertEqual(self.layer.read_bytes(), COMMITTED)

    def test_skip_reason_names_the_absent_inputs(self):
        rebuild_parity(self.gate, "layer/", [], ["layer/records.jsonl"],
                       ["work/source_manifest.json", "work/repos"],
                       root=self.root)
        self.assertIn("work/source_manifest.json", self.detail())
        self.assertIn("work/repos", self.detail())


class TestResidualSummary(unittest.TestCase):
    def test_names_the_field_path(self):
        committed = b'{"id": "r1", "a": 1}\n{"id": "r2", "a": 2}\n'
        rebuilt = b'{"id": "r1", "a": 1}\n{"id": "r2", "a": 3}\n'
        out = residual_summary(committed, rebuilt, jsonl=True)
        self.assertIn("1/2 records differ", out)
        self.assertIn("a", out)

    def test_no_residual_for_identical_bytes(self):
        self.assertEqual(residual_summary(COMMITTED, COMMITTED), "no residual")

    def test_json_document(self):
        committed = json.dumps({"x": 1, "y": {"z": 2}}).encode("utf-8")
        rebuilt = json.dumps({"x": 1, "y": {"z": 3}}).encode("utf-8")
        out = residual_summary(committed, rebuilt, jsonl=False)
        self.assertIn("document differs", out)
        self.assertIn("y.z", out)


class TestDerivedChainIsLikeForLike(unittest.TestCase):
    """The derived/ replay must be the documented pipeline, not one stage."""

    def test_chain_includes_the_citation_resolution_stage(self):
        # The citation stage of this replay is `replay_v1_citation_pins.py`,
        # not `resolve_citations.py`. The resolver reads only git-ignored
        # clones (work/wt, work/repos, work/sources, work/source_manifest.json)
        # that a partial checkout does not have, so it cannot re-derive the
        # published pins: its own write-guard refuses the run (exit 1) rather
        # than shrink the authoritative 639 pins to the ~553 the remaining
        # clones can resolve. `replay_v1_citation_pins.py` re-applies those
        # exact SHAs and their resolution metadata verbatim -- it is the same
        # offline stage used to publish the committed layer, so it is the
        # citation-resolution stage a like-for-like replay must include.
        # See reports/phase5_fixes_repro.md, "Fix 1". Adding the resolver back
        # would make the gate fail reproducibility, so that is guarded too.
        scripts = [c[0] for c in DERIVED_CHAIN]
        self.assertIn("scripts/replay_v1_citation_pins.py", scripts)
        self.assertNotIn("scripts/resolve_citations.py", scripts)

    def test_chain_includes_the_record_hash_migration(self):
        self.assertIn(("scripts/build_derived.py", ["--migrate-record-hashes"]),
                      DERIVED_CHAIN)

    def test_chain_starts_with_the_build_stage(self):
        self.assertEqual(DERIVED_CHAIN[0], ("scripts/build_derived.py", []))

    def test_every_written_file_is_in_the_snapshot_set(self):
        # derived/records.jsonl, derived/manifest.json and stage 5's own
        # report all have to be restored, or the check would leave the tree
        # changed.
        for rel in ("derived/records.jsonl", "derived/manifest.json",
                    "reports/citation_resolution.json"):
            self.assertIn(rel, DERIVED_FILES)

    def test_the_citation_inputs_are_the_documented_ones(self):
        from check_reproducibility import DERIVED_CITATION_INPUTS
        self.assertIn("work/source_manifest.json", DERIVED_CITATION_INPUTS)
        self.assertIn("work/repos", DERIVED_CITATION_INPUTS)


# ---------------------------------------------------------------------------
# Vbeta: cache-present and cache-absent rebuild parity
# ---------------------------------------------------------------------------
#
# The original Vbeta gate skipped itself whenever work/hydration_cache was
# absent. That hid a real corruption: with no cache the purge dropped every
# hydrated row and overwrote nine tracked files. build_vbeta.py now uses the
# committed hydrated rows as the authoritative hydration source when the cache
# is absent, so the same replay is byte-identical offline. These tests exercise
# that path with tiny temp roots — no network, no work/ cache in the real repo.

_HYDRATED = {
    "finding_id": "r1",
    "source_id": "src",
    "description": "x" * 140,
    "code_context": [{"snippet": "pragma solidity ^0.8.0; contract X {}",
                      "source_url": "https://example.invalid/x"}],
    "hydrated_by": "scripts/hydrate_vbeta_v4.py",
    "evidence": {"hydration_status": "LIVE"},
    "dataset_version": "vbeta-1.0",
}
_UNHYDRATED = {
    "finding_id": "r2",
    "source_id": "src",
    "description": "metadata only",
    "evidence": {},
    "dataset_version": "vbeta-1.0",
}
_HYDRATED_BENCH = {
    "task_id": "U_r1", "finding_id": "r1", "answer": "solidity",
    "answer_key_status": "labeled",
    "input": {"title": "t", "source_id": "src",
              "code": _HYDRATED["code_context"][0]["snippet"][:1000],
              "code_source": "https://example.invalid/x"},
}
_UNHYDRATED_BENCH = {
    "task_id": "U_r2", "finding_id": "r2", "answer": "unknown",
    "answer_key_status": "labeled",
    "input": {"title": "t", "source_id": "src"},
}


def _dump(path: Path, rows) -> None:
    _write(path, "".join(json.dumps(r, sort_keys=True) + "\n" for r in rows))


class TestVbetaHydrationSource(unittest.TestCase):
    """The cache-absent path must re-inline committed hydration, not skip."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.derived = self.root / "Vbeta" / "derived_vbeta"
        self.derived.mkdir(parents=True)
        _dump(self.derived / "records.jsonl", [_HYDRATED])
        self._p1 = patch.object(B.V, "ROOT", self.root)
        self._p2 = patch.object(B.V, "DERIVED_VB", self.derived)
        self._p1.start()
        self._p2.start()

    def tearDown(self):
        self._p2.stop()
        self._p1.stop()
        self._tmp.cleanup()

    def test_cache_absent_is_detected(self):
        self.assertFalse(B._hydration_cache_available())

    def test_empty_cache_is_treated_as_absent(self):
        (self.root / "work" / "hydration_cache").mkdir(parents=True)
        self.assertFalse(B._hydration_cache_available())

    def test_cache_with_blobs_is_available(self):
        cache = self.root / "work" / "hydration_cache"
        cache.mkdir(parents=True)
        _write(cache / "blob.txt", "verbatim source bytes")
        self.assertTrue(B._hydration_cache_available())

    def test_committed_fields_are_reinlined_onto_base_rows(self):
        # r1 has a committed hydrated counterpart; r2 is an unrelated
        # newcomer that must stay unhydrated (and so route to quarantine).
        base = [
            {"finding_id": "r1", "description": "METADATA_ONLY boilerplate",
             "evidence": {}},
            dict(_UNHYDRATED),
        ]
        bench = [{"task_id": "U_r1", "finding_id": "r1",
                  "input": {"title": "t", "source_id": "src"}},
                 dict(_UNHYDRATED_BENCH)]
        n = B._hydrate_from_committed(base, bench, [])
        self.assertEqual(n, 1)
        self.assertEqual(base[0], _HYDRATED)
        # The row with no committed hydrated counterpart is left untouched,
        # so the purge still routes it to quarantine exactly as before.
        self.assertNotIn("code_context", base[1])
        self.assertEqual(bench[0]["input"]["code"],
                         _HYDRATED["code_context"][0]["snippet"][:1000])
        self.assertEqual(bench[0]["input"]["code_source"],
                         "https://example.invalid/x")
        self.assertNotIn("code", bench[1]["input"])

    def test_no_committed_rows_raises_instead_of_skipping(self):
        (self.derived / "records.jsonl").unlink()
        with self.assertRaises(RuntimeError):
            B._hydrate_from_committed([dict(_UNHYDRATED)], [], [])


class TestVbetaGateBothCacheModes(unittest.TestCase):
    """The Vbeta gate replays the builder in both modes, leaving no drift."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.gate = Gate(quiet=True)
        self.records = self.root / "Vbeta" / "derived_vbeta" / "records.jsonl"
        self.bench = (self.root / "Vbeta" / "benchmark_vbeta" /
                      "vbeta_U_language_routing.jsonl")
        _dump(self.records, [_HYDRATED])
        _dump(self.bench, [_HYDRATED_BENCH])
        # Inputs a real rebuild would produce before hydration/purge.
        _dump(self.root / "Vbeta" / "derived_vbeta" / "base_records.jsonl",
              [{"finding_id": "r1", "description": "METADATA_ONLY boilerplate",
                "evidence": {}}, dict(_UNHYDRATED)])
        _dump(self.root / "Vbeta" / "benchmark_vbeta" / "base_bench.jsonl",
              [{"task_id": "U_r1", "finding_id": "r1", "answer": "solidity",
                "answer_key_status": "labeled",
                "input": {"title": "t", "source_id": "src"}},
               dict(_UNHYDRATED_BENCH)])
        (self.root / "Vbeta" / "scripts").mkdir(parents=True)

    def tearDown(self):
        self._tmp.cleanup()

    def _install_builder(self, mode: str) -> None:
        """A tiny stand-in for build_vbeta.py that uses the real helpers.

        cache-absent mode calls the real _hydrate_from_committed() to supply
        the hydration before writing; cache-present mode just rewrites the
        deterministic cache-fed bytes. Both must reproduce committed bytes.
        """
        real_scripts = repr(str(ROOT / "Vbeta" / "scripts"))
        repo_scripts = repr(str(ROOT / "scripts"))
        root = repr(str(self.root))
        if mode == "drift":
            body = (
                "from pathlib import Path\n"
                f"root = Path({root})\n"
                "p = root / 'Vbeta' / 'derived_vbeta' / 'records.jsonl'\n"
                "p.write_text('', encoding='utf-8')\n"
            )
        else:
            body = (
                "import sys\n"
                "from pathlib import Path\n"
                f"sys.path.insert(0, {real_scripts})\n"
                f"sys.path.insert(0, {repo_scripts})\n"
                "import build_vbeta as B\n"
                f"root = Path({root})\n"
                "B.V.ROOT = root\n"
                "B.V.DERIVED_VB = root / 'Vbeta' / 'derived_vbeta'\n"
                "d = B.V.DERIVED_VB\n"
                "bench_dir = root / 'Vbeta' / 'benchmark_vbeta'\n"
                "if B._hydration_cache_available():\n"
                "    recs = B.V.read_jsonl(d / 'records.jsonl')\n"
                "    bench = B.V.read_jsonl(bench_dir / "
                "'vbeta_U_language_routing.jsonl')\n"
                "else:\n"
                "    recs = B.V.read_jsonl(d / 'base_records.jsonl')\n"
                "    bench = B.V.read_jsonl(bench_dir / 'base_bench.jsonl')\n"
                "    B._hydrate_from_committed(recs, bench, [])\n"
                "    recs = [r for r in recs if r.get('hydrated_by')]\n"
                "    bench = [t for t in bench if (t.get('input') or {}).get('code')]\n"
                "B.V.write_jsonl(d / 'records.jsonl', recs)\n"
                "B.V.write_jsonl(bench_dir / 'vbeta_U_language_routing.jsonl', bench)\n"
            )
        _write(self.root / "Vbeta" / "scripts" / "build_vbeta.py", body)

    def _run_gate(self):
        before = (self.records.read_bytes(), self.bench.read_bytes())
        result = rebuild_parity(self.gate, "Vbeta/", VBETA_CHAIN, VBETA_FILES,
                                [], root=self.root)
        return result, before

    def _assert_restored(self, before) -> None:
        self.assertEqual((self.records.read_bytes(), self.bench.read_bytes()),
                         before)
        self.assertFalse((self.bench.with_suffix(".jsonl.tmp")).exists())

    def test_cache_present_replay_is_byte_identical(self):
        cache = self.root / "work" / "hydration_cache"
        cache.mkdir(parents=True)
        _write(cache / "blob.txt", "verbatim")
        self._install_builder("cache")
        result, before = self._run_gate()
        self.assertEqual(self.gate.rows[-1]["status"], "PASS",
                         self.gate.rows[-1]["detail"])
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["changed"], [])
        self._assert_restored(before)

    def test_cache_absent_replay_is_byte_identical(self):
        # No work/hydration_cache at all: the clean-CI case.
        self._install_builder("cache")
        result, before = self._run_gate()
        self.assertEqual(self.gate.rows[-1]["status"], "PASS",
                         self.gate.rows[-1]["detail"])
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["changed"], [])
        self._assert_restored(before)

    def test_drift_still_fails_gate_and_restores_committed_bytes(self):
        self._install_builder("drift")
        result, before = self._run_gate()
        self.assertEqual(self.gate.rows[-1]["status"], "FAIL")
        self.assertEqual(result["status"], "differs")
        self.assertIn("Vbeta/derived_vbeta/records.jsonl", result["changed"])
        self._assert_restored(before)

    def test_gate_file_set_covers_every_purge_managed_artifact(self):
        for rel in ("Vbeta/derived_vbeta/records.jsonl",
                    "Vbeta/derived_vbeta/candidate_ledger.jsonl",
                    "Vbeta/derived_vbeta/manifest.json",
                    "Vbeta/derived_vbeta/quarantine.jsonl",
                    "Vbeta/splits_vbeta/split.json",
                    "Vbeta/benchmark_vbeta/vbeta_U_language_routing.jsonl",
                    "Vbeta/benchmark_vbeta/vbeta_manifest.json",
                    "Vbeta/present_snapshot.json"):
            self.assertIn(rel, VBETA_FILES)
        self.assertEqual(VBETA_CHAIN, [("Vbeta/scripts/build_vbeta.py", [])])


if __name__ == "__main__":
    unittest.main(verbosity=2)
