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
        from vlun import BENCHMARK_FAMILIES, ROOT as VROOT
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
