"""Tests for the V3.2 blocked-run recovery records (spec item 7).

Covers three things:

  1. the record validator rejects the dishonest shapes this work could most
     plausibly fall into (a "recovery" claimed while the blocker is still set,
     a different fork block or hardfork with no scope_change note, a modified
     PoC with no overlay, an artefact hash that does not match the file, an L5
     without attacker-side profit, any L6 claim);
  2. the attempt artefacts actually committed under
     ``experiments_v3/<run>/attempt_N/`` pass that same validator, keep the
     pinned source and the root artefacts intact, and never claim a level the
     log does not show;
  3. ``reports/v3/v32_unblock_attempts.json`` still agrees with a fresh
     recomputation from those artefacts (counts are never hand-typed).

Run:  python -m unittest tests.test_v32_unblock_records
"""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import unblock_v32_runs as U  # noqa: E402
import redact_machine_paths as redact  # noqa: E402

RUNS = ("burgerswap", "gamma", "prisma", "shibatoken")
FIXTURES = ROOT / "tests" / "fixtures" / "broken"


def committed_attempts():
    rows = []
    for run in RUNS:
        for adir in sorted((ROOT / "experiments_v3" / run).glob("attempt_*")):
            if (adir / "result.json").is_file():
                rows.append((run, adir, read(adir / "result.json")))
    return rows


def read(p: Path) -> dict:
    return json.loads(p.read_text(encoding="utf-8"))


def has_error(errs, needle):
    return any(needle.lower() in e.lower() for e in errs)


class TestBrokenFixturesRejected(unittest.TestCase):
    """Each fixture is a record that must NOT validate."""

    def assert_fixture(self, name, needle):
        d = FIXTURES / name
        self.assertTrue((d / "result.json").is_file(),
                        f"missing fixture {name}")
        errs = U.validate_attempt_dir(d)
        self.assertTrue(errs, f"{name}: expected a validation error, got none")
        self.assertTrue(
            has_error(errs, needle),
            f"{name}: expected an error about {needle!r}, got {errs}")

    def test_recovery_claimed_while_blocker_stands(self):
        self.assert_fixture("claims_recovery_with_blocker", "failure_reason")

    def test_fork_block_changed_without_scope_note(self):
        self.assert_fixture("fork_block_changed_no_scope_note", "scope_change")

    def test_poc_changed_without_overlay(self):
        self.assert_fixture("poc_modified_without_overlay", "overlay")

    def test_artefact_hash_mismatch(self):
        self.assert_fixture("hash_mismatch", "hash does not match")

    def test_l5_without_attacker_profit(self):
        self.assert_fixture("l5_without_attacker_profit", "L5")

    MY_FIXTURES = ("claims_recovery_with_blocker",
                   "fork_block_changed_no_scope_note",
                   "poc_modified_without_overlay", "hash_mismatch",
                   "l5_without_attacker_profit")

    def test_every_fixture_of_this_module_is_rejected(self):
        """Scoped to this module's fixtures: tests/fixtures/broken/ is shared
        with other validators, so only these five must be rejected here."""
        for name in self.MY_FIXTURES:
            errs = U.validate_attempt_dir(FIXTURES / name)
            self.assertTrue(errs, f"{name} validated clean; it is not a "
                                  "broken fixture")


class TestRecordRules(unittest.TestCase):
    """Rules exercised on in-memory records (no files involved)."""

    def base(self, **kw):
        rec = {
            "run": "prisma", "attempt": 3, "kind": "archive_provider",
            "status": "blocked", "failure_reason": "archive_state_unavailable",
            "level_awarded": "L3", "evidence_level_supported": "L3",
            "recovered": False,
            "fork_target_pinned_by_poc": {"alias": "mainnet", "kind": "tx",
                                          "value": "0xabc"},
            "fork_target_used": {"alias": "mainnet", "kind": "tx",
                                 "value": "0xabc"},
            "hardfork": "backend default (today's rules)",
            "poc_bytes_modified": False,
            "impact_check": {"claim_notes": []},
            "original_run": {"status": "blocked", "level_awarded": "L3"},
        }
        rec.update(kw)
        return rec

    def test_clean_record_passes(self):
        self.assertEqual(U.validate_attempt(self.base()), [])

    def test_hardfork_deviation_needs_note(self):
        errs = U.validate_attempt(self.base(hardfork="cancun"))
        self.assertTrue(has_error(errs, "scope_change"), errs)

    def test_note_without_deviation_is_dropped(self):
        errs = U.validate_attempt(self.base(scope_change="nothing changed"))
        self.assertTrue(has_error(errs, "although nothing deviated"), errs)

    def test_l6_is_never_awarded_by_an_attempt(self):
        rec = self.base(kind="block_fork_reconstruction",
                        level_awarded="L6", evidence_level_supported="L6",
                        status="violation_observed", failure_reason=None,
                        recovered=True, hardfork="cancun",
                        scope_change="pinned rule set",
                        profit_deltas=[{"attacker_side": True, "profit": 1}],
                        test={"test_function": "test_exploit"})
        errs = U.validate_attempt(rec)
        self.assertTrue(has_error(errs, "L6"), errs)

    def test_level_must_be_in_ladder(self):
        errs = U.validate_attempt(self.base(level_awarded="L7",
                                            evidence_level_supported="L7"))
        self.assertTrue(has_error(errs, "ladder"), errs)

    def test_supported_level_must_agree(self):
        errs = U.validate_attempt(self.base(level_awarded="L3",
                                            evidence_level_supported="L4"))
        self.assertTrue(has_error(errs, "disagrees"), errs)

    def test_blocked_attempt_needs_explicit_blocker(self):
        errs = U.validate_attempt(self.base(failure_reason=None))
        self.assertTrue(has_error(errs, "explicit failure_reason"), errs)

    def test_recovered_status_never_below_recovered_level(self):
        errs = U.validate_attempt(self.base(status="violation_observed"))
        self.assertTrue(has_error(errs, "recovered level"), errs)

    def test_level_never_dropped_below_the_root_run(self):
        errs = U.validate_attempt(self.base(level_awarded="L2",
                                           evidence_level_supported="L2"))
        self.assertTrue(has_error(errs, "below the level the root run"), errs)

    def test_archive_provider_attempt_must_not_claim_scope_change(self):
        errs = U.validate_attempt(self.base(
            scope_change="used a nearby block"))
        self.assertTrue(errs, "archive_provider must keep the pinned target")

    def test_gas_floor_replay_reason_is_an_archive_blocker(self):
        log = ("[FAIL: vm.createSelectFork: backend: failed replaying "
               "transaction; transaction validation error: gas floor (21680) "
               "exceeds the gas limit (21438)] setUp() (gas: 0)")
        status, reason, _ = U.classify(1, log, "", "test_exploit")
        self.assertEqual(status, "blocked")
        self.assertEqual(reason, "archive_state_unavailable")

    def test_test_frame_revert_is_a_result_not_a_missing_state(self):
        log = ("[FAIL: EvmError: Revert] testExploit() (block: 166873291) "
               "(gas: 124775)")
        status, reason, _ = U.classify(1, log, "", "testExploit")
        self.assertEqual(status, "test_failed")
        self.assertEqual(reason, "poc_reverted_on_pinned_fork")

    def test_pass_without_profit_is_l4_not_l5(self):
        log = ("[PASS] testExploit() (gas: 10)\nLogs:\n"
               "  BURGER exploited: 0\n  WBNB exploited: 100\n")
        status, _, _ = U.classify(0, log, "", "testExploit")
        self.assertEqual(status, "executed_no_profit_evidence")

    def test_mismatched_token_pair_is_not_profit(self):
        """A mkUSD 'before' must not be paired with a wstETH 'after'."""
        log = ("[PASS] test_exploit() (gas: 10)\nLogs:\n"
               "  Attacker start with ~1800 mkUSD:  1800000022022732637\n"
               "  start with wstETH balance before attack :  0\n"
               "  wstETH balance after attack:  1281797208306130557587\n")
        self.assertEqual(U.classify(0, log, "", "test_exploit")[0],
                         "executed_no_profit_evidence")
        ds = U.attacker_profit_evidence(log)
        self.assertFalse(any(d["valid_attacker_profit"] for d in ds), ds)

    def test_attacker_profit_on_one_asset_is_l5(self):
        log = ("[PASS] testExploit() (gas: 10)\nLogs:\n"
               "  Attacker ETH Balance Before exploit:  0\n"
               "  Attacker ETH Balance After exploit:  479393838338751000000\n")
        self.assertEqual(U.classify(0, log, "", "testExploit")[0],
                         "violation_observed")


class TestCommittedAttemptArtefacts(unittest.TestCase):
    """The real attempt directories: honest, hash-pinned, source-pinned."""

    def attempts(self):
        return committed_attempts()

    def test_there_are_attempts_for_the_blocked_runs(self):
        self.assertTrue(self.attempts(), "no attempt artefacts committed")

    def test_every_attempt_validates_clean(self):
        for run, adir, _ in self.attempts():
            with self.subTest(run=run, attempt=adir.name):
                self.assertEqual(U.validate_attempt_dir(adir), [])

    def test_every_attempt_keeps_the_original_blocker_visible(self):
        for run, adir, rec in self.attempts():
            with self.subTest(run=run, attempt=adir.name):
                self.assertIn("original_run", rec)
                self.assertEqual(rec["original_run"].get("status"), "blocked")
                self.assertEqual(rec["original_run"].get("level_awarded"), "L3")

    def test_blocked_attempts_keep_an_explicit_blocker(self):
        for run, adir, rec in self.attempts():
            if rec["status"] in U.RECOVERED:
                continue
            with self.subTest(run=run, attempt=adir.name):
                self.assertTrue(rec.get("failure_reason"),
                                "blocked attempt without a blocker")
                self.assertNotIn(rec["level_awarded"], ("L4", "L5", "L6"),
                                 "a blocked attempt cannot carry an executed "
                                 "level")

    def test_pinned_source_bytes_are_untouched(self):
        """Non-overlay attempts must run the byte-identical staged PoC."""
        for run in RUNS:
            root = read(ROOT / "experiments_v3" / run / "harness.json")
            for adir in sorted((ROOT / "experiments_v3" / run)
                               .glob("attempt_*")):
                if not (adir / "harness.json").is_file():
                    continue
                h = read(adir / "harness.json")
                with self.subTest(run=run, attempt=adir.name):
                    self.assertEqual(h["poc_sha256_original"],
                                     root["poc_sha256"])
                    self.assertEqual(h["clone_head"],
                                     read(ROOT / "experiments_v3" / run
                                          / "result.json")["clone_head"])

    def test_run_root_artefacts_are_unchanged(self):
        """The proof-hashes gate pins the run-root bytes; only subdirs were
        added, so every root artefact must still hash to what result.json
        records."""
        for run in RUNS:
            d = ROOT / "experiments_v3" / run
            rec = read(d / "result.json")
            for name, want in rec["artifact_hashes"].items():
                with self.subTest(run=run, artefact=name):
                    self.assertEqual(U.sha_file(d / name), want,
                                     f"{run}/{name} was modified")

    def test_attempts_never_write_at_the_run_root(self):
        """The attempt batch may only ADD files, and only inside an attempt
        directory, and every artefact it wrote is the one its own manifest
        describes.

        The invariant is asserted structurally, not as a byte-frozen
        "nothing under experiments_v3/ ever differs from HEAD".  A later
        canonical builder is allowed to rewrite the bytes of a committed
        transcript: the machine-path redaction
        (`scripts/redact_machine_paths.py`) does exactly that, and in the
        same pass re-points the digest that names the file, so the
        provenance chain over the redacted bytes stays closed.  A rule that
        cannot tell that apart from a silent edit is not a rule; it only
        breaks on any legitimate later repair.  The rules below are the ones
        a silent edit actually breaks.

        1. nothing tracked under experiments_v3/ was DELETED or RENAMED --
           the attempt work never removes a committed artefact;
        2. every path git reports as new lives inside an
           `experiments_v3/<run>/attempt_N/` directory: the attempt work
           writes into its own attempt directory and nowhere else;
        3. every attempt directory holds exactly the files its own
           `result.json` names, plus that `result.json`: the attempt work
           wrote into its own directory and nowhere else in the attempt
           tree, so it wrote nothing at a run root;
        4. the provenance chain over the bytes on disk is closed: the
           canonical report and each attempt's own manifest agree on every
           artefact digest, those digests match the files, and every run
           root's artefacts still hash to what its own `result.json`
           records;
        5. a tracked artefact whose bytes differ from HEAD is one the
           canonical machine-path redaction owns, and the redaction is a
           no-op on it: the tree holds the canonical redacted bytes, so the
           modification is attributable to a builder and leaves no
           un-redacted operator path behind.

        The "Added" wording of the original rule still holds: a new path
        covers both an unstaged new dir (`??`) and the same dir once it has
        been staged (`A `).
        """
        p = subprocess.run(["git", "-c", "core.safecrlf=false", "status",
                            "--porcelain", "--", "experiments_v3"],
                           cwd=str(ROOT), capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=120)
        self.assertEqual(p.returncode, 0, p.stderr[:400])
        for line in (p.stdout or "").splitlines():
            tag, path = line[:2], line[3:].strip()
            if tag in ("??", "A "):
                # rule 2: a new path is an attempt directory, never a
                # run-root artefact.
                self.assertRegex(path.replace("\\", "/"),
                                 r"experiments_v3/[^/]+/attempt_\d+/",
                                 f"unexpected new path {path}")
                continue
            if tag in ("D ", " D", "R ", " R"):
                self.fail(f"{tag} {path}: the attempt batch must never "
                          "delete or rename a committed artefact")
            # any other tag is a modification; rule 5 checks it below.
            self.assertIn(tag, (" M", "M "), f"{tag} {path}: unexpected change")

        d = subprocess.run(["git", "-c", "core.safecrlf=false", "diff",
                            "--name-status", "--find-renames", "HEAD", "--",
                            "experiments_v3"],
                           cwd=str(ROOT), capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=120)
        self.assertEqual(d.returncode, 0, d.stderr[:400])
        modified: list[str] = []
        for line in (d.stdout or "").splitlines():
            code, _, path = line.partition("\t")
            code = code.strip()
            if code == "A":
                continue
            if code in ("D", "R"):
                self.fail(f"{line}: an attempt batch may only add files "
                          "under experiments_v3/, never change a tracked "
                          "run-root artefact")
            self.assertEqual(code, "M", f"{line}: unexpected change")
            modified.append(path)

        # rule 3: an attempt directory holds exactly what its own manifest
        # names.  A file the manifest does not name was written by something
        # other than the attempt work, and a file the manifest names but
        # that is not on disk is a missing artefact.
        for _run, adir, rec in committed_attempts():
            with self.subTest(run=_run, attempt=adir.name):
                named = set((rec.get("artifact_hashes") or {})) | {"result.json"}
                on_disk = {f.relative_to(adir).as_posix()
                           for f in adir.rglob("*") if f.is_file()}
                self.assertEqual(on_disk, named,
                                 f"{adir}: the attempt directory holds "
                                 f"{sorted(on_disk - named)} that its own "
                                 f"manifest does not name, or is missing "
                                 f"{sorted(named - on_disk)}")

        # rule 4: the chain over the bytes on disk is closed.
        report = read(ROOT / "reports" / "v3" / "v32_unblock_attempts.json")
        for entry in report["attempts"]:
            adir = ROOT / entry["path"]
            rec = read(adir / "result.json")
            self.assertEqual(entry.get("artifact_hashes"),
                             rec.get("artifact_hashes"),
                             f"{entry['path']}: the canonical report and the "
                             "attempt's own manifest disagree on the "
                             "artefact digests")
            for name, want in (rec.get("artifact_hashes") or {}).items():
                self.assertEqual(U.sha_file(adir / name), want,
                                 f"{entry['path']}/{name} does not match the "
                                 "digest its manifest records")
        for run_dir in sorted(p_ for p_ in (ROOT / "experiments_v3").iterdir()
                              if p_.is_dir()):
            root_result = run_dir / "result.json"
            if not root_result.is_file():
                continue
            rec = read(root_result)
            for name, want in (rec.get("artifact_hashes") or {}).items():
                self.assertEqual(U.sha_file(run_dir / name), want,
                                 f"{run_dir.name}/{name} was modified")

        # rule 5: a modified artefact is a canonical redaction, not an edit.
        for rel in modified:
            with self.subTest(path=rel):
                self.assertTrue(redact.in_scope(rel),
                                f"{rel} was modified but is not a file the "
                                "canonical machine-path redaction owns")
                data = (ROOT / rel).read_bytes()
                out, _hits = redact.redact_bytes(data)
                self.assertEqual(out, data,
                                 f"{rel} is not in the canonical redacted "
                                 "state: an un-redacted machine path is left "
                                 "behind")


    def test_overlay_hash_matches_the_original_when_overlay_is_used(self):
        """overlay files must be recorded against the pinned original bytes."""
        for run, adir, rec in self.attempts():
            if not rec.get("poc_bytes_modified"):
                continue
            with self.subTest(run=run, attempt=adir.name):
                self.assertTrue((adir / "overlay").is_dir())
                h = read(adir / "harness.json")
                for rel, meta in h["overlay"].items():
                    ov = adir / "overlay" / Path(rel).parent / Path(rel).name
                    self.assertEqual(U.sha_file(ov),
                                     meta["overlay_poc_sha256"])
                    orig = read(ROOT / "experiments_v3" / run
                                / "harness.json")["poc_sha256"]
                    self.assertEqual(meta["original_poc_sha256"], orig)
                    self.assertNotEqual(meta["overlay_poc_sha256"], orig)

    def test_provider_and_fork_are_pinned_in_every_harness(self):
        for run, adir, _ in self.attempts():
            h = read(adir / "harness.json")
            with self.subTest(run=run, attempt=adir.name):
                for key in ("rpc_provider", "fork_target_pinned_by_poc",
                            "fork_target_used", "compiler_version",
                            "remappings", "submodule_shas", "test_function"):
                    self.assertIn(key, h)
                self.assertTrue(h["submodule_shas"].get("lib/forge-std"))
                self.assertTrue(h["remappings"])

    def test_no_attempt_claims_l6(self):
        for run, adir, rec in self.attempts():
            self.assertNotEqual(rec.get("level_awarded"), "L6")

    def test_recovered_attempts_state_their_evidence_check(self):
        for run, adir, rec in self.attempts():
            if rec["status"] not in U.RECOVERED:
                continue
            with self.subTest(run=run, attempt=adir.name):
                self.assertTrue(rec.get("impact_check"))
                self.assertTrue(rec.get("test", {}).get("test_function"))
                so = (adir / "stdout.txt").read_text(encoding="utf-8",
                                                     errors="replace")
                self.assertIn("[PASS]", so)


class TestReportConsistency(unittest.TestCase):
    def test_report_counts_match_recomputation(self):
        path = ROOT / "reports" / "v3" / "v32_unblock_attempts.json"
        self.assertTrue(path.is_file(), "report missing; run "
                                        "scripts/unblock_v32_runs.py")
        committed = read(path)
        fresh = U.build_report(U.collect_attempts())
        for key in ("attempts_total", "attempts_recovered", "attempts_blocked",
                    "attempts_with_scope_change", "provider_access_unavailable",
                    "validation_error_count"):
            self.assertEqual(committed[key], fresh[key], key)
        for key in ("by_status", "by_failure_reason", "by_kind",
                    "best_level_per_run"):
            self.assertEqual(committed[key], fresh[key], key)
        self.assertEqual(sorted(a["path"] for a in committed["attempts"]),
                         sorted(a["path"] for a in fresh["attempts"]))

    def test_markdown_reports_every_attempt(self):
        md = (ROOT / "reports" / "v3" / "v32_unblock_attempts.md").read_text(
            encoding="utf-8")
        for run, adir, _ in committed_attempts():
            self.assertIn(adir.name, md)
            self.assertIn(run, md)

    def test_recovered_run_still_lists_the_original_blocker(self):
        committed = read(ROOT / "reports" / "v3" / "v32_unblock_attempts.json")
        for run, best in committed["best_level_per_run"].items():
            if best in ("L4", "L5"):
                continue
            with self.subTest(run=run):
                rows = [a for a in committed["attempts"] if a["run"] == run]
                self.assertTrue(any(r["failure_reason"] for r in rows),
                                "an unrecovered run must still show a blocker")

    def test_canonical_layers_not_promoted_by_this_work(self):
        """Promotion is the main agent's job; these bytes must be untouched."""
        proof = read(ROOT / "reports" / "v3" / "experimental_proof.json")
        for run in proof["runs"]:
            if run.get("experiment") not in RUNS:
                continue
            self.assertEqual(run.get("status"), "blocked",
                             f"{run['experiment']} was promoted here")
            self.assertEqual(run.get("level_awarded"), "L3")


if __name__ == "__main__":
    unittest.main(verbosity=2)
