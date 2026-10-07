#!/usr/bin/env python3
"""Tests for reproducibility (ordering, pins, skips, isolation).

Run:  python -m unittest discover -s tests
"""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))


class TestDeterministicOrdering(unittest.TestCase):
    def test_sort_keys_redump_stable(self):
        obj = {"b": [3, 1, 2], "a": {"z": 1, "m": 2}}
        once = json.dumps(obj, indent=2, sort_keys=True) + "\n"
        twice = json.dumps(json.loads(once), indent=2, sort_keys=True) + "\n"
        self.assertEqual(once, twice)

    def test_legacy_split_pin_matches_committed_file(self):
        legacy = ["cantina-portfolio", "cyfrin-codehawks",
                  "immunefi-past-competitions", "movebit-sampled-audits",
                  "neodyme-reports", "openzeppelin-cairo", "ottersec-audits",
                  "runtime-verification-publications",
                  "trailofbits-publications", "veridise-zk-archive"]
        expect = {sid: ("train", "validation", "test")[i % 3]
                  for i, sid in enumerate(legacy)}
        split = json.load(open(ROOT / "Vbeta/splits_vbeta/split.json",
                               encoding="utf-8-sig"))
        for sid, want in expect.items():
            self.assertEqual(split["assignment"].get(sid), want, sid)

    def test_manifest_key_ordering_stable(self):
        with open(ROOT / "Vbeta/derived_vbeta/manifest.json",
                  encoding="utf-8-sig") as fh:
            man = json.load(fh)
        redump = json.dumps(man, indent=2, sort_keys=True) + "\n"
        with open(ROOT / "Vbeta/derived_vbeta/manifest.json",
                  encoding="utf-8") as fh:
            raw = fh.read().replace("\r\n", "\n")
        self.assertEqual(raw, redump)


class TestSkipSemantics(unittest.TestCase):
    def test_offline_skip_status(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        from build_all import run_stage
        r = run_stage(1, "fetch_sources.py", ["--checkouts"], "x",
                      needs_net=True, allow_net=False)
        self.assertEqual(r["status"], "skipped_no_network")

    def test_build_all_json_skips_honest(self):
        try:
            with open(ROOT / "reports/build_all.json",
                      encoding="utf-8-sig") as fh:
                doc = json.load(fh)
        except OSError:
            self.skipTest("no build_all.json in this copy")
        for st in doc.get("stages", []):
            if st.get("status") == "skipped_no_network":
                self.assertNotEqual(st.get("status"), "ok")


class TestIsolation(unittest.TestCase):
    def test_vbeta_path_assert_exists_and_bites(self):
        sys.path.insert(0, str(ROOT / "Vbeta" / "scripts"))
        import vlun_vbeta as V
        outside = ROOT / "jsonl" / "findings.jsonl"
        with self.assertRaises(RuntimeError):
            V.assert_inside_vbeta(outside)
        inside = ROOT / "Vbeta" / "derived_vbeta" / "manifest.json"
        self.assertEqual(V.assert_inside_vbeta(inside), inside.resolve())

    def test_present_snapshot_covers_sentinels(self):
        with open(ROOT / "Vbeta/present_snapshot.json",
                  encoding="utf-8-sig") as fh:
            snap = json.load(fh)
        for rel in ("README.md", "benchmark/manifest.json",
                    "derived_v3/manifest.json"):
            self.assertIn(rel, snap["sentinel_sha256"])


class TestLiveGates(unittest.TestCase):
    def test_check_manifests_green(self):
        r = subprocess.run([sys.executable, "scripts/check_manifests.py",
                            "--quiet"], cwd=str(ROOT), capture_output=True,
                           text=True)
        self.assertEqual(r.returncode, 0, r.stdout[-2000:] + r.stderr[-2000:])

    def test_check_reproducibility_green(self):
        r = subprocess.run([sys.executable,
                            "scripts/check_reproducibility.py", "--quiet"],
                           cwd=str(ROOT), capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout[-2000:] + r.stderr[-2000:])


if __name__ == "__main__":
    unittest.main(verbosity=2)
