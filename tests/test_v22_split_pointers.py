#!/usr/bin/env python3
"""The v2.2 split pointers must reproduce from the derived records.

Regression (2026-10-25): the derived_v2_2 layer was rebuilt after the
experiment-artefact `bytes` field landed, but splits_v2_2 was not. All 37
experiment-bearing records kept stale `record_sha256` digests in their split
pointer, validate.py checks 37/44 went critical, and the K-Q benchmark
rebuild refused to produce rows. The owner scripts' `--check` modes did not
compare against committed bytes and reported "0 problems" throughout.

These tests are pure reads plus the owner scripts' own --check: no layer is
written. Run:  python -m unittest tests.test_v22_split_pointers

Retired benchmark families are an explicit exception to the rebuild-parity test
below. Their rows are published history written by the builder as it stood at
retirement time, so a later correction to that builder -- family M's answer key
now comes from the adjudicated `experiment_view`, not the immutable source
claim -- must not be read as licence to rewrite `benchmark/retired_families/`.
A retired family is checked frozen, carried and self-consistent instead; what
its rows would have to say if it were ever emitted live is guarded by
`build_benchmark_v22.m_answer_key_problems` and
`tests.test_v22_adjudicated_consumers`.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

SPLITS = ("train", "validation", "test")


def read_jsonl(path: Path) -> list:
    with path.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonical(row: dict) -> str:
    return json.dumps(row, sort_keys=True, ensure_ascii=False)


class TestSplitPointersMatchTheDerivedRecords(unittest.TestCase):
    def setUp(self):
        self.records = {r["id"]: r for r in
                        read_jsonl(ROOT / "derived_v2_2" / "records.jsonl")}
        self.pointers = []
        for split in SPLITS:
            for p in read_jsonl(ROOT / "splits_v2_2" / f"{split}.jsonl"):
                if p.get("layer") == "v2.2":
                    self.pointers.append((split, p))

    def test_every_v2_2_pointer_hash_equals_its_record_hash(self):
        self.assertTrue(self.pointers, "no v2.2 split pointers found")
        bad = []
        for split, p in self.pointers:
            rec = self.records.get(p["id"])
            if rec is None:
                bad.append(f"{split}: {p['id']} has no derived record")
                continue
            if p.get("record_sha256") != sha256_text(canonical(rec)):
                bad.append(f"{split}: {p['id']} record_sha256 mismatch")
        self.assertEqual(bad, [],
                         "stale split pointers: run python "
                         "scripts/build_splits_v22.py")

    def test_the_pointer_set_covers_the_derived_records_exactly(self):
        pointed = {p["id"] for _s, p in self.pointers}
        self.assertEqual(pointed, set(self.records),
                         "derived records and split pointers disagree on "
                         "membership")

    def test_the_kq_rebuild_matches_the_committed_task_files(self):
        import build_benchmark_v22 as bb
        from vlun import BENCHMARK_FAMILIES, RETIRED_FAMILIES, ROOT as VROOT
        tasks, info = bb.build()
        self.assertEqual(info["problems"], [],
                         "the K-Q rebuild refuses: " +
                         "; ".join(info["problems"][:5]))
        man = json.loads(
            (VROOT / "benchmark" / "manifest.json").read_text(encoding="utf-8"))
        for key, rows in tasks.items():
            name = BENCHMARK_FAMILIES[key][0]
            entry = (man.get("tasks") or {}).get(name) or {}
            path = VROOT / (entry.get("file") or f"benchmark/{name}.jsonl")
            on_disk = read_jsonl(path) if path.exists() else []
            if f"{name}.jsonl" in RETIRED_FAMILIES:
                # A retired family is published history: its rows were written
                # by the builder as it stood when it was retired, and fixing
                # that builder afterwards (family M now answers from the
                # adjudicated experiment view) must never become a reason to
                # rewrite the frozen file. What is required of a retired family
                # is that it is frozen, carried and self-consistent -- and that
                # the live answer keys it would emit are guard-checked, which
                # tests.test_v22_adjudicated_consumers proves.
                self.assertIn("retired_families", path.as_posix(),
                              f"{name}: retired rows are not under "
                              "benchmark/retired_families/")
                self.assertEqual(entry.get("status"), "retired",
                                 f"{name}: retired rows with "
                                 f"status={entry.get('status')!r}")
                self.assertEqual(entry.get("tasks"), len(on_disk),
                                 f"{name}: manifest tasks disagree with the "
                                 "frozen row count")
                continue
            self.assertEqual(
                canonical(rows), canonical(on_disk),
                f"{name}: rebuilt tasks differ from {path.relative_to(VROOT)}")


class TestOwnerChecksReportCurrent(unittest.TestCase):
    def test_the_owner_scripts_agree_the_layer_is_current(self):
        for script in ("scripts/build_splits_v22.py",
                       "scripts/build_benchmark_v22.py"):
            r = subprocess.run([sys.executable, script, "--check"],
                               cwd=str(ROOT), capture_output=True,
                               text=True, timeout=900)
            self.assertEqual(
                r.returncode, 0,
                f"{script} --check must pass on the committed tree: "
                + r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
