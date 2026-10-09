"""Every committed artefact hash must match the bytes on disk.

experiments_v3/*/result.json records a sha256 per run artefact. Those
hashes are the provenance claim for the v3.2 execution layer: they say
"these exact bytes were produced by forge". A hash that does not match the
shipped file is a broken claim, not a cosmetic issue.

This gate fails on any mismatch, so a CRLF-emitting writer (which produced
27 unverifiable hashes before) cannot reintroduce them silently.
"""
from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXP = ROOT / "experiments_v3"


class TestArtefactHashes(unittest.TestCase):
    def test_results_exist(self):
        results = sorted(EXP.glob("*/result.json"))
        self.assertTrue(results, "no experiments_v3 result.json found")

    def test_recorded_hashes_match_disk(self):
        bad = []
        checked = 0
        for res in sorted(EXP.glob("*/result.json")):
            doc = json.loads(res.read_text(encoding="utf-8"))
            for name, want in (doc.get("artifact_hashes") or {}).items():
                f = res.parent / name
                if not f.is_file():
                    bad.append(f"{res.parent.name}/{name}: missing")
                    continue
                checked += 1
                got = hashlib.sha256(f.read_bytes()).hexdigest()
                if got != want:
                    bad.append(f"{res.parent.name}/{name}: {want[:12]} != "
                               f"{got[:12]}")
        self.assertEqual(bad, [], f"{len(bad)} artefact hash mismatch(es)")
        self.assertGreater(checked, 0)

    def test_required_artefacts_per_run(self):
        # Every artefact a result.json claims in artifact_hashes must exist.
        # Not a fixed six-file list: a run blocked before staging (e.g. the
        # bybit pilot) legitimately has no harness manifest and does not
        # claim one.
        for res in sorted(EXP.glob("*/result.json")):
            doc = json.loads(res.read_text(encoding="utf-8"))
            claimed = set(doc.get("artifact_hashes") or {})
            self.assertTrue(claimed, f"{res.parent.name}: claims no artefacts")
            missing = [n for n in sorted(claimed)
                       if not (res.parent / n).is_file()]
            self.assertEqual(missing, [],
                             f"{res.parent.name}: claims {missing}")

    def test_proof_runs_have_full_artefact_set(self):
        proof = json.loads((ROOT / "reports" / "v3" / "experimental_proof.json")
                           .read_text(encoding="utf-8"))
        need = ("command.txt", "stdout.txt", "stderr.txt", "toolchain.txt",
                "harness.json")
        for run in proof.get("runs", []):
            slug = run.get("experiment") or ""
            d = EXP / slug
            self.assertTrue(d.is_dir(), f"{slug}: proof run has no directory")
            missing = [n for n in need if not (d / n).is_file()]
            self.assertEqual(missing, [], f"{slug}: {missing}")

    def test_no_crlf_in_run_artefacts(self):
        # A CRLF artefact hashes differently on Windows vs Linux, which is
        # what made the recorded hashes unverifiable in the first place.
        bad = []
        for res in sorted(EXP.glob("*/result.json")):
            for n in ("command.txt", "stdout.txt", "stderr.txt",
                      "toolchain.txt", "harness.json", "result.json"):
                f = res.parent / n
                if f.is_file() and b"\r\n" in f.read_bytes():
                    bad.append(f"{res.parent.name}/{n}")
        self.assertEqual(bad, [])


class TestV32RecordsCiteRealArtefacts(unittest.TestCase):
    def test_l4_plus_artefact_dir_exists(self):
        recs = [json.loads(l) for l in
                (ROOT / "derived_v3" / "records.jsonl").open(encoding="utf-8")
                if l.strip()]
        bad = []
        for r in recs:
            if r.get("verification_level") not in ("L4", "L5", "L6"):
                continue
            d = (r.get("experiment") or {}).get("artifact_dir")
            if not d or not (ROOT / d).is_dir():
                bad.append(r["finding_id"])
        self.assertEqual(bad, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)