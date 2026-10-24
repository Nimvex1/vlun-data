#!/usr/bin/env python3
"""Tests for the machine-path gate and the record hash scheme.

Two independent guards live here, because they answer the same question in
two different ways - "can this artefact be checked by somebody else?" - and
both must hold:

  1. No committed artefact may carry a machine-local absolute path. The
     gate is `scripts/check_no_machine_paths.py`; it detects paths by shape,
     so it fails the same way for every operator and every CI runner.

  2. Every derived record's digest must say which bytes it covers. A digest
     without a stated scheme is not checkable, so the verifier rejects it.

Run:  python -m unittest tests.test_no_machine_paths -v
"""

from __future__ import annotations

import ast
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import build_derived as bd  # noqa: E402
import check_no_machine_paths as gate  # noqa: E402
from vlun_io import read_jsonl  # noqa: E402

DERIVED_RECORDS = ROOT / "derived" / "records.jsonl"

# The fixture paths are assembled from parts on purpose: the gate scans this
# test file as well, and a test file that spelled a machine path out in
# full would be a machine path in the repository.
WIN_LEAK = "C:" + "\\Users\\" + "somebody" + "\\project\\out.txt"
POSIX_LEAK = "/" + "home" + "/" + "somebody" + "/project/out.txt"
JSON_LEAK = json.dumps({"command": WIN_LEAK.replace("\\", "\\\\")})

# One scan of the whole repository, shared by the tests that need it.
_SCAN: list | None = None


def repo_scan() -> list:
    global _SCAN
    if _SCAN is None:
        _SCAN = gate.scan()
    return _SCAN


# ---------------------------------------------------------------------------
# 1. the machine-path gate
# ---------------------------------------------------------------------------

class MachinePathGateTests(unittest.TestCase):
    """The gate must catch a machine path, and the repository must be clean."""

    def _scan_text(self, name: str, text: str) -> list:
        """Scan one synthetic file through the real gate code."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / name).write_text(text, encoding="utf-8")
            with mock.patch.object(gate, "ROOT", root):
                return gate.scan_files([name])

    def test_windows_operator_path_is_an_operator_leak(self):
        findings = self._scan_text("notes.txt", f"built at {WIN_LEAK}\n")
        self.assertTrue(findings, "the gate found nothing")
        self.assertEqual(findings[0].category, "OPERATOR_LEAK")
        self.assertEqual(findings[0].kind, "windows_user_profile")
        self.assertEqual(findings[0].line, 1)

    def test_posix_operator_path_is_an_operator_leak(self):
        findings = self._scan_text("notes.txt", f"built at {POSIX_LEAK}\n")
        self.assertTrue(findings, "the gate found nothing")
        self.assertEqual(findings[0].category, "OPERATOR_LEAK")
        self.assertEqual(findings[0].kind, "posix_home")

    def test_a_path_escaped_inside_a_json_string_is_found(self):
        findings = self._scan_text("row.json", JSON_LEAK + "\n")
        self.assertTrue(findings, "the gate found nothing")
        self.assertEqual(findings[0].category, "OPERATOR_LEAK")

    def test_repository_relative_and_url_paths_are_not_leaks(self):
        findings = self._scan_text(
            "notes.txt",
            "see derived/records.jsonl and "
            "https://github.com/code-423n4/2024-04-noya/blob/"
            "7e7b0ffb53b516b95c7900d25fb00af8f108727f/contracts/x.sol\n")
        self.assertEqual(findings, [], f"false positives: {findings}")

    def test_the_gate_itself_fails_on_a_file_with_an_operator_path(self):
        """The gate must not pass a file that carries a machine path."""
        for text in (WIN_LEAK, POSIX_LEAK):
            with self.subTest(text=text):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    (root / "leak.txt").write_text(text, encoding="utf-8")
                    with mock.patch.object(gate, "ROOT", root), \
                            mock.patch.object(gate, "candidate_files",
                                              return_value=["leak.txt"]):
                        rc = gate.main(["--quiet"])
                    self.assertEqual(rc, 1,
                                     "the gate passed a file with a "
                                     "machine-local path")

    def test_the_gate_passes_the_repository(self):
        rc = gate.main(["--quiet"])
        self.assertEqual(rc, 0)

    def test_the_repository_has_no_unlisted_machine_path(self):
        """Clean apart from the documented allowlist.

        Every hit must be classified as GENUINE (a path that is not the
        operator's: an upstream quote, a redaction placeholder, a command
        example) or PENDING (a real operator path in a file another agent
        owns, tracked here with the change that clears it). Anything else
        fails the build.
        """
        unlisted = [f for f in repo_scan() if f.category == "OPERATOR_LEAK"]
        self.assertEqual(
            [(f.file, f.line, f.kind) for f in unlisted], [],
            "unlisted machine paths: " + "; ".join(
                f"{f.file}:{f.line} {f.kind}" for f in unlisted[:20]))

    def test_every_allowlist_entry_states_why_it_is_allowed(self):
        for allow in list(gate.ALLOWLIST) + list(gate.PENDING):
            with self.subTest(glob=allow.path_glob):
                self.assertTrue(allow.reason.strip(),
                                "allowlist entry without a reason")
                self.assertIn(allow.category, ("GENUINE", "PENDING"))
                if allow.category == "PENDING":
                    self.assertTrue(allow.owner.strip())
                    self.assertTrue(allow.required_change.strip())

    def test_the_scan_does_not_depend_on_this_machine_home(self):
        """The gate must not read the current machine's home directory.

        A gate that only knew about the current user's home would pass on
        the machine that produced the artefact and fail everywhere else.
        The check is on the parsed module, not on the prose: the docstring
        names the anti-pattern it avoids.
        """
        source = (ROOT / "scripts" / "check_no_machine_paths.py").read_text(
            encoding="utf-8")
        tree = ast.parse(source)
        used = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                used.add(node.attr)
            elif isinstance(node, ast.Name):
                used.add(node.id)
        for forbidden in ("expanduser", "environ", "home", "getenv"):
            self.assertNotIn(forbidden, used,
                             f"the gate reads {forbidden}")


# ---------------------------------------------------------------------------
# 2. the record hash scheme
# ---------------------------------------------------------------------------

class RecordHashSchemeTests(unittest.TestCase):
    """A digest must state which bytes it covers, and it must be checkable."""

    ROW = {"finding": {"id": "x/1"}, "severity": "medium", "note": "a"}

    def _record(self, **overrides) -> dict:
        ev = {
            "record_sha256": bd.canonical_row_hash(self.ROW),
            "record_sha256_version": bd.RECORD_HASH_SCHEME_V2,
            "record_sha256_v2": bd.canonical_row_hash(self.ROW),
            "record_sha256_v2_version": bd.RECORD_HASH_SCHEME_V2,
        }
        ev.update(overrides)
        return {"id": "x/1", "original_evidence": ev}

    def test_a_record_without_a_scheme_marker_is_rejected(self):
        rec = {"id": "x/1", "original_evidence": {
            "record_sha256": bd.canonical_row_hash(self.ROW)}}
        problems = bd.verify_record_hashes([rec], {"x/1": self.ROW})
        self.assertTrue(problems, "an unversioned digest was accepted")
        self.assertEqual(problems[0]["field"], "record_sha256_version")

    def test_a_record_with_an_unknown_scheme_is_rejected(self):
        rec = self._record(record_sha256_version="v9-something")
        problems = bd.verify_record_hashes([rec], {"x/1": self.ROW})
        self.assertTrue(problems)
        self.assertEqual(problems[0]["field"], "record_sha256_version")

    def test_a_record_with_a_wrong_digest_is_rejected(self):
        rec = self._record(record_sha256="0" * 64)
        problems = bd.verify_record_hashes([rec], {"x/1": self.ROW})
        self.assertTrue(problems)
        self.assertEqual(problems[0]["field"], "record_sha256")

    def test_a_versioned_record_is_accepted(self):
        problems = bd.verify_record_hashes([self._record()],
                                           {"x/1": self.ROW})
        self.assertEqual(problems, [])

    def test_a_digest_over_an_injected_verdict_is_rejected_without_its_verdict(
            self):
        """A digest that covers a row with a PoC verdict injected into it
        cannot be checked without the verdict, and is never reported as
        reproduced when the verdict is unavailable."""
        injected = dict(self.ROW)
        injected[bd._VERIFICATION_KEY] = "reproduced"
        rec = self._record(
            record_sha256=bd.canonical_row_hash(injected),
            record_sha256_version=bd.RECORD_HASH_SCHEME_BUILDER_ROW)
        problems = bd.verify_record_hashes([rec], {"x/1": self.ROW})
        self.assertTrue(problems)
        self.assertIn("not available", problems[0]["problem"])

    def test_the_committed_records_state_their_scheme(self):
        records = read_jsonl(DERIVED_RECORDS)
        self.assertTrue(records)
        for rec in records:
            ev = rec.get("original_evidence") or {}
            with self.subTest(record=rec.get("id")):
                self.assertTrue(ev.get("record_sha256_version"),
                                "no scheme marker")
                self.assertEqual(ev.get("record_sha256_v2_version"),
                                 bd.RECORD_HASH_SCHEME_V2)
                self.assertTrue(ev.get("record_sha256_v2"))

    def test_the_committed_records_verify_against_the_committed_rows(self):
        records = read_jsonl(DERIVED_RECORDS)
        committed = bd.committed_source_rows()
        problems = bd.verify_record_hashes(records, committed)
        self.assertEqual(problems, [],
                         f"{len(problems)} records do not verify: "
                         f"{problems[:5]}")

    def test_the_committed_layer_states_both_historical_schemes(self):
        records = read_jsonl(DERIVED_RECORDS)
        schemes: dict[str, int] = {}
        for rec in records:
            v = (rec.get("original_evidence") or {}).get("record_sha256_version")
            schemes[v] = schemes.get(v, 0) + 1
        self.assertEqual(schemes.get(bd.RECORD_HASH_SCHEME_COMMITTED_ROW), 567)
        self.assertEqual(
            schemes.get(bd.RECORD_HASH_SCHEME_BUILDER_ROW), 155)
        self.assertEqual(len(records), 722)

    def test_the_historical_digests_are_not_rewritten(self):
        """The historical digest and the v2 digest are different values for
        the records whose historical digest covers a transformed row, which
        is what proves the historical value was carried forward rather than
        silently recalculated."""
        records = read_jsonl(DERIVED_RECORDS)
        committed = bd.committed_source_rows()
        differing = 0
        for rec in records:
            ev = rec.get("original_evidence") or {}
            if ev.get("record_sha256_version") != bd.RECORD_HASH_SCHEME_BUILDER_ROW:
                continue
            row = committed[rec["id"]]
            self.assertNotEqual(ev.get("record_sha256"),
                                bd.canonical_row_hash(row))
            differing += 1
        self.assertEqual(differing, 155)

    def test_the_v2_digest_is_reproducible_from_the_committed_row(self):
        records = read_jsonl(DERIVED_RECORDS)
        committed = bd.committed_source_rows()
        for rec in records:
            ev = rec.get("original_evidence") or {}
            with self.subTest(record=rec.get("id")):
                self.assertEqual(ev.get("record_sha256_v2"),
                                 bd.canonical_row_hash(committed[rec["id"]]))


if __name__ == "__main__":
    unittest.main()
