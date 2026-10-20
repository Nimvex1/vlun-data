"""Integrity tests for the non-EVM execution pilot (spec item 9).

These fail on the broken fixtures under tests/fixtures/broken/nonevm-*: a
recorded hash that no longer matches the bytes on disk, an "executed" run with
no named assertion, a compile-only run promoted to L5, a blocked run with no
blocker string.  They also check that the shipped reports agree with the
artefacts on disk, so a count cannot be edited into a report without the run
existing behind it.

tests/fixtures/broken/ is shared with other spec items, so this module's
fixtures are namespaced `nonevm-*` and are rebuilt here when a parallel
cleanup removes them (that has happened during this work).
"""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "nonevm"))

import common as C  # noqa: E402
import run_pilot as P  # noqa: E402

GOOD = ROOT / "tests" / "fixtures" / "nonevm_good"
BROKEN = ROOT / "tests" / "fixtures" / "broken"

_ASSERT_OK = {"name": "tests::pow", "kind": "named_test",
              "expected": {"test_status": "ok"},
              "observed": {"test_status": "ok"}, "met": True,
              "not_just_exit_code": True}
_ASSERT_REFUSED = {"name": "tests::pow", "kind": "named_test",
                   "expected": {"test_status": "failed"},
                   "observed": {"test_status": "failed"}, "met": True,
                   "not_just_exit_code": True}
_OUT = "test tests::pow ... ok\n\ntest result: ok. 1 passed; 0 failed\n"


def _write_run(root: Path, slug: str, *, status, outcome, ladder, kind,
               assertion, stdout, stderr, break_hash=False):
    d = root / slug
    d.mkdir(parents=True, exist_ok=True)
    files = {
        "command.txt": b"cargo test --release -- --exact tests::pow\n",
        "toolchain.txt": json.dumps({"toolchain": {"tool": "cargo"},
                                     "prerequisites": []}, indent=2).encode(),
        "harness.json": json.dumps(
            {"pin": {"commit": "a" * 40}, "toolchain": {"tool": "cargo"},
             "run_kind": kind, "isolation": "local scratch"},
            indent=2, sort_keys=True).encode() + b"\n",
        "stdout.txt": stdout.encode(),
        "stderr.txt": stderr.encode(),
    }
    if assertion is not None:
        files["assertion.json"] = (json.dumps(assertion, indent=2,
                                              sort_keys=True).encode() + b"\n")
    arts = {}
    for name, blob in files.items():
        (d / name).write_bytes(blob)
        arts[name] = {"bytes": len(blob),
                      "sha256": hashlib.sha256(blob).hexdigest()}
    if break_hash and "stdout.txt" in arts:
        arts["stdout.txt"]["sha256"] = "0" * 64
    res = {"schema": C.SCHEMA, "platform": "cosmwasm",
           "record_id": "rust:CWA-2024-002", "run_slug": slug,
           "claim": "fixture claim", "status": status, "outcome": outcome,
           "ladder": ladder, "toolchain": {"tool": "cargo"},
           "prerequisites": [], "pin": {"commit": "a" * 40,
                                        "requested_ref": "=1.5.3",
                                        "resolved_by": "crates.io version pin"},
           "assertion": assertion,
           "run": {"argv": ["cargo", "test"],
                   "exit_code": 0 if status == "executed" else 101,
                   "seconds": 1.0, "run_kind": kind,
                   "isolation": "local scratch"},
           "blocker": None, "licence": {"upstream": "Apache-2.0"},
           "artefacts": arts}
    (d / "result.json").write_bytes(json.dumps(res, indent=2,
                                               sort_keys=True).encode() + b"\n")
    return d


def _ensure_fixtures():
    """Rebuild this module's fixtures if a parallel cleanup removed them."""
    if not (GOOD / "cw-1.5.3-release-pow" / "result.json").exists():
        _write_run(GOOD, "cw-1.5.3-release-pow", status="executed",
                   outcome="claim_reproduced", ladder="L5",
                   kind="test_harness", assertion=_ASSERT_OK, stdout=_OUT,
                   stderr="")
    if not (GOOD / "cw-1.5.4-release-pow" / "result.json").exists():
        _write_run(GOOD, "cw-1.5.4-release-pow", status="executed",
                   outcome="executed_without_impact", ladder="L4",
                   kind="test_harness", assertion=_ASSERT_REFUSED,
                   stdout="test tests::pow ... FAILED\n", stderr="")
    want = {
        "nonevm-executed-hash-mismatch": dict(
            status="executed", outcome="claim_reproduced", ladder="L5",
            kind="test_harness", assertion=_ASSERT_OK, stdout=_OUT, stderr="",
            break_hash=True),
        "nonevm-executed-without-assertion": dict(
            status="executed", outcome="claim_reproduced", ladder="L5",
            kind="test_harness", assertion=None, stdout=_OUT, stderr=""),
        "nonevm-compile-only-promoted-to-l5": dict(
            status="executed", outcome="claim_reproduced", ladder="L5",
            kind="compile_only", assertion=_ASSERT_OK,
            stdout="error: could not compile\n", stderr=""),
        "nonevm-blocked-without-blocker": dict(
            status="blocked", outcome="blocked", ladder="L1", kind="none",
            assertion=None, stdout="", stderr=""),
    }
    for slug, kw in want.items():
        if not (BROKEN / slug / "result.json").exists():
            _write_run(BROKEN, slug, **kw)


_ensure_fixtures()


def _read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class FixtureIntegrity(unittest.TestCase):
    def test_good_fixtures_validate_clean(self):
        for d in sorted(p for p in GOOD.iterdir() if p.is_dir()):
            self.assertEqual(C.validate_run_dir(d), [], f"{d.name} must be clean")

    def test_broken_fixture_is_rejected(self):
        cases = [
            ("nonevm-executed-hash-mismatch", "artefact_hash_mismatch stdout.txt"),
            ("nonevm-executed-without-assertion", "executed_without_assertion"),
            ("nonevm-compile-only-promoted-to-l5",
             "ladder_escalation_from_compile_only_run"),
            ("nonevm-blocked-without-blocker", "blocked_run_without_blocker_string"),
        ]
        for slug, expected in cases:
            with self.subTest(slug=slug):
                errors = C.validate_run_dir(BROKEN / slug)
                self.assertTrue(errors, f"{slug} must not validate")
                self.assertTrue(any(expected in e for e in errors), (slug, errors))

    def test_every_nonevm_broken_fixture_is_rejected(self):
        """tests/fixtures/broken/ is shared between spec items, so this only
        asserts over this module's own namespaced fixtures."""
        mine = sorted(p for p in BROKEN.iterdir()
                      if p.is_dir() and p.name.startswith("nonevm-"))
        self.assertEqual(len(mine), 4, [p.name for p in mine])
        for d in mine:
            self.assertTrue(C.validate_run_dir(d),
                            f"{d.name} unexpectedly validated clean")

    def test_good_fixture_pair_is_the_reference_l6_shape(self):
        """One pin pair: the same named assertion reproduces on one pin and is
        refused on the other, which is the only way L6 may be claimed."""
        runs = [_read(p / "result.json") for p in sorted(
            d for d in GOOD.iterdir() if d.is_dir())]
        ceil = P.ceiling_ladder(runs)
        self.assertEqual(ceil["rust:CWA-2024-002"]["record_ceiling"], "L6")
        single = P.ceiling_ladder([runs[0]])
        self.assertEqual(single["rust:CWA-2024-002"]["record_ceiling"], "L5",
                         "a reproduction on one pin alone must never reach L6")

    def test_compile_only_cannot_reach_l4(self):
        d = BROKEN / "nonevm-compile-only-promoted-to-l5"
        rec = _read(d / "result.json")
        self.assertEqual(rec["run"]["run_kind"], "compile_only")
        errors = " ".join(C.validate_run_dir(d))
        self.assertIn("compile_only_promoted_to_L5", errors)

    def test_malformed_run_field_is_rejected_not_crashed(self):
        d = BROKEN / "nonevm-blocked-without-blocker"
        res = _read(d / "result.json")
        res["run"] = "prisma"          # a field of the wrong type must not crash
        with tempfile.TemporaryDirectory() as td:
            tmp = _write_run(Path(td), "_tmp_malformed", status="executed",
                             outcome="claim_reproduced", ladder="L5",
                             kind="test_harness", assertion=_ASSERT_OK,
                             stdout=_OUT, stderr="")
            (tmp / "result.json").write_text(json.dumps(res), encoding="utf-8")
            errors = C.validate_run_dir(tmp)
            self.assertTrue(any("run_field_not_an_object" in e for e in errors),
                            errors)


class VocabularyAndArtefacts(unittest.TestCase):
    def test_vocabulary_is_closed(self):
        self.assertEqual(C.LADDER, ["L0", "L1", "L2", "L3", "L4", "L5", "L6"])
        self.assertEqual(set(C.OUTCOMES), {
            "blocked", "compile_failed", "executed_without_impact",
            "inconclusive", "claim_reproduced"})
        self.assertEqual(set(C.PLATFORM_KEYS), set(C.PLATFORM_ORDER))

    def test_pilot_artefacts_on_disk_are_self_consistent(self):
        if not C.load_runs():
            self.skipTest("no pilot artefacts yet")
        integrity = C.validate_pilot()
        self.assertTrue(integrity["clean"],
                        json.dumps(integrity["error_dirs"], indent=2))

    def test_report_counts_equal_recomputed_counts(self):
        runs = C.load_runs()
        if not runs:
            self.skipTest("no pilot artefacts yet")
        self.assertTrue(C.REPORT_JSON.exists(), "run scripts/nonevm/run_pilot.py")
        rep = _read(C.REPORT_JSON)
        self.assertEqual(rep["counts"]["runs_total"], len(runs))
        self.assertEqual(rep["counts"]["executed_runs"], sum(
            1 for r in runs if r.get("status") == "executed"))
        self.assertEqual(rep["counts"]["unique_records_executed"], len(
            {r["record_id"] for r in runs if r.get("status") == "executed"}))
        per_platform: dict[str, int] = {}
        for r in runs:
            per_platform[r["platform"]] = per_platform.get(r["platform"], 0) + 1
        for plat, n in per_platform.items():
            self.assertEqual(rep["platforms"][plat]["runs"], n, plat)

    def test_every_executed_run_names_an_assertion_and_a_pin(self):
        for r in C.load_runs():
            if r.get("status") != "executed":
                continue
            a = r.get("assertion") or {}
            self.assertTrue(a.get("name"),
                            f"{r['run_slug']}: executed with no assertion")
            self.assertIsNotNone(a.get("observed"))
            self.assertIsNotNone(a.get("expected"))
            pin = r.get("pin") or {}
            self.assertTrue(pin.get("requested_ref") or pin.get("commit"),
                            r["run_slug"])

    def test_claim_reproduced_runs_are_never_control_cells(self):
        for r in C.load_runs():
            if r.get("outcome") == "claim_reproduced":
                name = (r.get("assertion") or {}).get("name") or ""
                self.assertNotIn("control", name,
                                 f"{r['run_slug']}: a non-vacuity control is "
                                 "not a reproduction")


class AdapterPrerequisiteMatrix(unittest.TestCase):
    def test_adapters_expose_the_prerequisite_matrix(self):
        for mod_name in ("cosmwasm", "solana_anchor", "aptos_move", "sui_move",
                         "cairo_scarb"):
            with self.subTest(platform=mod_name):
                mod = __import__(mod_name)
                rows = mod.prerequisites()
                self.assertTrue(rows, mod_name)
                for row in rows:
                    self.assertIn("tool", row, (mod_name, row))
                    self.assertIn("install_status", row, (mod_name, row))
                    if row["install_status"] == "missing":
                        self.assertTrue(row.get("install_command"),
                                        f"{mod_name}: a missing prerequisite must "
                                        "record the exact install command")
                if not C.candidates_for(mod.PLATFORM):
                    continue
                specs, blocked = mod.plan(C.load_records())
                self.assertIsInstance(specs, list)
                self.assertIsInstance(blocked, list)


if __name__ == "__main__":
    unittest.main()
