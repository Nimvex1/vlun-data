"""Every committed artefact hash must match the bytes on disk.

experiments_v3/*/result.json records a sha256 per run artefact. Those
hashes are the provenance claim for the v3.2 execution layer: they say
"these exact bytes were produced by forge". A hash that does not match the
shipped file is a broken claim, not a cosmetic issue.

This gate fails on any mismatch, so a CRLF-emitting writer (which produced
27 unverifiable hashes before) cannot reintroduce them silently.

The same claim is made by the other experiment layers, so the gate covers
them too: experiments/ (the v1 run records), experiments_v2_2/ (the v2.2 run
records and their index) and the v3 record files. The hashing schemes and the
table of recorded-but-unreproducible digests live in
scripts/reconcile_proof_artefact_hashes.py, so the gate and the scheme have
one source of truth.

A digest that cannot be reproduced from the committed bytes is not silently
rewritten: it has to be listed as unresolved, with the reason, or this gate
fails.
"""
from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import reconcile_proof_artefact_hashes as rpa  # noqa: E402

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

    def test_proof_hashes_match_disk(self):
        """experimental_proof.json is the SOURCE v32_execution.py reads.

        test_proof_runs_have_full_artefact_set only checked that the files
        exist. The hashes recorded here were stale for all 6 runs -- the
        CRLF recompute in c124c7e fixed result.json and left this copy
        behind -- so the canonical record files inherited a pointer that
        did not match the bytes it claimed to prove. Existence is not
        provenance; this is.
        """
        proof = json.loads((ROOT / "reports" / "v3" / "experimental_proof.json")
                           .read_text(encoding="utf-8"))
        bad = []
        checked = 0
        for run in proof.get("runs", []):
            d = run.get("artifact_dir")
            for name, want in (run.get("artifact_hashes") or {}).items():
                f = ROOT / d / name
                if not f.is_file():
                    bad.append(f"{d}/{name}: missing")
                    continue
                checked += 1
                got = hashlib.sha256(f.read_bytes()).hexdigest()
                if got != want:
                    bad.append(f"{d}/{name}: {want[:12]} != {got[:12]}")
        self.assertEqual(bad, [],
                         f"{len(bad)} proof artefact hash mismatch(es)")
        self.assertGreater(checked, 0)

    def test_record_hashes_match_disk(self):
        """The record files copy the proof's hashes; they must still match."""
        bad = []
        checked = 0
        for name in ("jsonl_v3/findings.jsonl", "derived_v3/records.jsonl"):
            p = ROOT / name
            if not p.is_file():
                continue
            for line in p.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                exp = (json.loads(line).get("experiment") or {})
                d = exp.get("artifact_dir")
                for artifact, want in (exp.get("artifact_hashes") or {}).items():
                    f = ROOT / d / artifact
                    if not f.is_file():
                        bad.append(f"{name}: {d}/{artifact} missing")
                        continue
                    checked += 1
                    got = hashlib.sha256(f.read_bytes()).hexdigest()
                    if got != want:
                        bad.append(f"{name}: {d}/{artifact} "
                                   f"{want[:12]} != {got[:12]}")
        self.assertEqual(bad, [],
                         f"{len(bad)} record artefact hash mismatch(es)")
        self.assertGreater(checked, 0)

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


class TestExperimentLayersArtefactHashes(unittest.TestCase):
    """The v1 and v2.2 layers make the same provenance claim as v3."""

    def _layer(self, label):
        for lay in rpa.LAYERS:
            if lay[0] == label:
                return lay
        raise KeyError(label)

    def _check_layer(self, label):
        _, base, pattern, key, scheme = self._layer(label)
        bad = []
        checked = 0
        for res in sorted(base.glob(pattern)):
            doc = json.loads(res.read_text(encoding="utf-8"))
            if res.name == "index.json":
                entries = []
                for e in doc.get("experiments") or []:
                    for n, v in (e.get(key) or {}).items():
                        entries.append((base / e["experiment_id"] / n, v))
            else:
                entries = [(res.parent / n, v)
                           for n, v in (doc.get(key) or {}).items()]
            for path, value in entries:
                want = rpa.want_of(value)
                if want is None:
                    continue
                rel = path.relative_to(ROOT).as_posix()
                if not path.is_file():
                    bad.append(f"{rel}: missing")
                    continue
                checked += 1
                ok, _ = rpa.matches(want, path.read_bytes(), scheme)
                if not ok:
                    bad.append(f"{rel}: {want[:12]} does not match the committed bytes")
        self.assertGreater(checked, 0, f"{label}: no artefact hash was checked")
        return checked, bad

    def test_v1_experiment_hashes_match_committed_bytes(self):
        checked, bad = self._check_layer("v1 experiments")
        known = rpa.unresolved_index()
        unexpected = [b for b in bad if b.split(":")[0] not in known]
        self.assertEqual(unexpected, [],
                         f"{len(unexpected)} v1 artefact hash mismatch(es) are not "
                         "recorded as unresolved")
        self.assertEqual(len(bad), len(unexpected) + len(
            [b for b in bad if b.split(":")[0] in known]),
            "every unresolved v1 mismatch must be in the table")

    def test_v22_experiment_hashes_match_committed_bytes(self):
        checked, bad = self._check_layer("v2.2 experiments")
        self.assertEqual(bad, [], f"{len(bad)} v2.2 artefact hash mismatch(es)")

    def test_v22_index_hashes_match_committed_bytes(self):
        checked, bad = self._check_layer("v2.2 index")
        self.assertEqual(bad, [], f"{len(bad)} v2.2 index hash mismatch(es)")

    def test_unresolved_mismatches_state_their_reason(self):
        for path, entry in rpa.unresolved_index().items():
            with self.subTest(path=path):
                self.assertTrue(entry.get("reason"),
                                "an unresolved mismatch must state the reason")
                self.assertTrue(entry.get("recorded_hash_version"),
                                "an unresolved mismatch must state the scheme its "
                                "recorded value was produced under")
                self.assertEqual(len(entry.get("recorded_sha256", "")), 64)
                self.assertEqual(len(entry.get("committed_sha256", "")), 64)

    def test_every_layer_that_claims_hashes_is_scanned(self):
        """A layer may not silently drop out of the scan."""
        scanned = {lay[0] for lay in rpa.LAYERS}
        for required in ("v1 experiments", "v2.2 experiments", "v2.2 index",
                         "nonevm experiments", "v3 experiments"):
            self.assertIn(required, scanned)

    def test_hashing_scheme_is_versioned_and_documented(self):
        self.assertTrue(rpa.HASH_VERSION)
        for name in ("sha256-v2", "sha256-v1-text", "sha256-v1-raw",
                     "sha256-v1-bytes"):
            self.assertIn(name, rpa.SCHEME_SUMMARY,
                          "every scheme the records use must be documented")
            self.assertTrue(rpa.SCHEME_SUMMARY[name])

    def test_non_verifiable_categories_are_named(self):
        """A category that cannot be hash-verified here is named, not ignored."""
        cats = rpa.NON_VERIFIABLE_HASH_CATEGORIES
        self.assertTrue(cats, "the non-verifiable categories must be named")
        for c in cats:
            self.assertTrue(c.get("category"))
            self.assertTrue(c.get("why_not_verifiable"))
            self.assertTrue(c.get("checked_by"))


class TestV32RecordsCiteRealArtefacts(unittest.TestCase):
    def test_l4_plus_artefact_dir_exists(self):
        recs = [json.loads(line) for line in
                (ROOT / "derived_v3" / "records.jsonl").open(encoding="utf-8")
                if line.strip()]
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
