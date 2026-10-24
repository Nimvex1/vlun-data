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
    resolve_citations -> the record-hash migration), not one stage.

Run:  python -m unittest tests.test_reproducibility_parity -v
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from check_reproducibility import (  # noqa: E402
    DERIVED_CHAIN,
    DERIVED_FILES,
    Gate,
    rebuild_parity,
    residual_summary,
)

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
        scripts = [c[0] for c in DERIVED_CHAIN]
        self.assertIn("scripts/resolve_citations.py", scripts)

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
