"""The L6 claims must be backed by the two-revision evidence they name.

`l6_verified_patch` is a claim about a controlled comparison: the same test,
the same assertions and byte-identical harness bytes must have run on the
vulnerable revision (where the violation is observed) and on the fixed
revision (where the property holds). A run that failed on one side and passed
on the other is not enough: if the two sides did not run the same harness
bytes, the difference in outcome could be a property of the harness rather
than of the protocol.

These tests read the committed bytes and fail when

  a. a claim is recorded as two-revision verified but the two revisions did not
     share the same test, assertions and harness digests, or the recorded
     commit ids are missing or do not resolve;
  b. an artefact hash in experiments/ or experiments_v2_2/ does not match the
     committed bytes and the mismatch is not explicitly recorded as unresolved;
  c. the recorded verdict is not the verdict the committed artefacts support,
     so a downgrade cannot be quietly overwritten (or quietly kept once the
     evidence changed).

The hashing scheme and the table of unresolved historical digests live in
scripts/reconcile_proof_artefact_hashes.py, so there is one source of truth
for both the gate and these tests.
"""
from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import reconcile_proof_artefact_hashes as rpa  # noqa: E402

REPORT = ROOT / "reports" / "verified_experiments.json"
EXPERIMENTS = ROOT / "experiments"

VERIFIED = "l6_verified_patch"
PARTIAL_VERDICT = "l6_partial_two_revision_evidence"
UNVERIFIABLE_VERDICT = "l6_unverifiable_two_revision_evidence"
DOWNGRADED = (PARTIAL_VERDICT, UNVERIFIABLE_VERDICT)

SHA1_RE = re.compile(r"^[0-9a-f]{40}$")


def load_report() -> dict:
    return json.loads(REPORT.read_text(encoding="utf-8"))


def revision_result(finding_id: str, label: str) -> dict | None:
    p = EXPERIMENTS / finding_id.replace("/", "__") / label / "result.json"
    if not p.is_file():
        return None
    return json.loads(p.read_text(encoding="utf-8"))


def forge_test_files(digests: dict) -> dict:
    return {n: d for n, d in (digests or {}).items() if n.endswith(".t.sol")}


def derive_evidence(finding_id: str) -> tuple[str, list[str]]:
    """Derive the two-revision status from the committed artefacts alone.

    This is an independent re-derivation of what the builder computes, so a
    hand-edited report cannot pass.
    """
    missing: list[str] = []
    sides = {lbl: revision_result(finding_id, lbl)
             for lbl in ("vulnerable", "fixed")}
    absent = [lbl for lbl, d in sides.items() if d is None]
    if absent:
        return "UNVERIFIABLE", ["no committed result.json for the "
                                + " and ".join(absent) + " revision"]
    v, f = sides["vulnerable"], sides["fixed"]
    vd = v.get("harness_file_digests") or {}
    fd = f.get("harness_file_digests") or {}
    if v.get("harness_digest") != f.get("harness_digest"):
        missing.append("the two revisions did not run byte-identical harness bytes")
    if forge_test_files(vd) != forge_test_files(fd):
        missing.append("the two revisions did not run the same test file bytes")
    commits = [(v.get("repository") or {}).get("commit"),
               (f.get("repository") or {}).get("commit")]
    if not all(commits) or not all(c and SHA1_RE.match(c) for c in commits):
        missing.append("the recorded revisions do not name two full commit ids")
    if len(set(commits)) != 2:
        missing.append("both revisions name the same commit")
    if missing:
        return "PARTIAL", missing
    dv = v.get("declared_expected_status")
    df = f.get("declared_expected_status")
    polarity = ((dv == "fail" and df == "pass"
                 and v.get("status") == "fail" and f.get("status") == "pass")
                or (dv == "pass" and df == "fail"
                    and v.get("status") == "pass" and f.get("status") == "fail"))
    if not polarity:
        return "UNVERIFIABLE", ["the recorded run outcomes do not show the declared "
                                "polarity"]
    return "VERIFIED_TWO_REVISION", []


def expected_verdict(finding_id: str, exp: dict) -> str:
    """The verdict the committed artefacts support."""
    status, _ = derive_evidence(finding_id)
    revs = exp.get("revisions") or {}
    v = (revs.get("vulnerable") or {}).get("status")
    f = (revs.get("fixed") or {}).get("status")
    dv = (revs.get("vulnerable") or {}).get("declared_expected_status")
    df = (revs.get("fixed") or {}).get("declared_expected_status")
    polarity_held = ((dv == "fail" and df == "pass" and v == "fail" and f == "pass")
                     or (dv == "pass" and df == "fail" and v == "pass" and f == "fail"))
    if not polarity_held:
        return "inconclusive"
    if status == "VERIFIED_TWO_REVISION":
        return VERIFIED
    if status == "PARTIAL":
        return PARTIAL_VERDICT
    return UNVERIFIABLE_VERDICT


class TestL6TwoRevisionClaims(unittest.TestCase):
    def setUp(self):
        self.report = load_report()
        self.experiments = {e["finding_id"]: e
                            for e in self.report.get("experiments", [])}

    def test_report_is_not_empty(self):
        self.assertTrue(self.experiments, "no recorded experiments")

    def test_verified_claims_share_the_same_harness(self):
        """(a) A two-revision verified claim must rest on identical harness bytes."""
        for fid, exp in sorted(self.experiments.items()):
            if exp.get("verdict") != VERIFIED:
                continue
            with self.subTest(finding_id=fid):
                v = revision_result(fid, "vulnerable")
                f = revision_result(fid, "fixed")
                self.assertIsNotNone(v, "no committed vulnerable artefact")
                self.assertIsNotNone(f, "no committed fixed artefact")
                self.assertTrue(v.get("harness_digest"),
                                "the vulnerable run recorded no harness digest")
                self.assertEqual(v.get("harness_digest"), f.get("harness_digest"),
                                 "the two revisions ran different harness bytes")
                vd = v.get("harness_file_digests") or {}
                fd = f.get("harness_file_digests") or {}
                self.assertEqual(sorted(vd), sorted(fd),
                                 "the two revisions ran different harness files")
                for name in sorted(set(vd) & set(fd)):
                    self.assertEqual(vd[name], fd[name],
                                     f"{name} differs between the two revisions")
                self.assertEqual(forge_test_files(vd), forge_test_files(fd),
                                 "the two revisions did not run the same test file")
                self.assertTrue(forge_test_files(vd), "no test file was recorded")

    def test_verified_claims_name_two_resolvable_commits(self):
        """(a) The recorded commit ids must be present and resolvable."""
        for fid, exp in sorted(self.experiments.items()):
            if exp.get("verdict") != VERIFIED:
                continue
            with self.subTest(finding_id=fid):
                commits = []
                for label in ("vulnerable", "fixed"):
                    d = revision_result(fid, label) or {}
                    c = (d.get("repository") or {}).get("commit")
                    self.assertTrue(c, f"the {label} revision names no commit")
                    self.assertRegex(c, SHA1_RE, "the commit id is not a full sha1")
                    commits.append(c)
                self.assertNotEqual(commits[0], commits[1],
                                    "both revisions name the same commit")
                resolution = ((exp.get("two_revision_evidence") or {})
                              .get("commit_resolution") or {})
                self.assertIn(resolution.get("status"),
                              ("resolved", "skipped_clone_unavailable"),
                              "the commit resolution is neither a pass nor a visible "
                              "skip")
                if resolution.get("status") == "resolved":
                    self.assertEqual(sorted(resolution.get("resolved") or []),
                                     sorted(commits),
                                     "a recorded commit does not resolve")
                    self.assertEqual(resolution.get("unresolved"), [])
                else:
                    # A clean checkout has no clone of the audited repository.
                    # That is a skip, and it has to say so.
                    self.assertEqual(resolution.get("unresolved"), sorted(commits))
                    self.assertTrue(resolution.get("note"),
                                    "a skipped resolution must say why")

    def test_verified_claims_show_the_declared_polarity(self):
        for fid, exp in sorted(self.experiments.items()):
            if exp.get("verdict") != VERIFIED:
                continue
            with self.subTest(finding_id=fid):
                revs = exp.get("revisions") or {}
                v = revs.get("vulnerable") or {}
                f = revs.get("fixed") or {}
                self.assertEqual(v.get("declared_expected_status"), "fail")
                self.assertEqual(f.get("declared_expected_status"), "pass")
                self.assertEqual(v.get("status"), "fail",
                                 "the vulnerable revision did not fail")
                self.assertEqual(f.get("status"), "pass",
                                 "the fixed revision did not pass")

    def test_verified_claims_record_their_evidence(self):
        for fid, exp in sorted(self.experiments.items()):
            if exp.get("verdict") != VERIFIED:
                continue
            with self.subTest(finding_id=fid):
                ev = exp.get("two_revision_evidence") or {}
                self.assertEqual(ev.get("status"), "VERIFIED_TWO_REVISION")
                self.assertEqual(ev.get("missing_evidence"), [])
                self.assertTrue(ev.get("harness_digests_match"))
                self.assertTrue(ev.get("test_file_digests_match"))

    def test_downgraded_claims_name_the_missing_evidence(self):
        for fid, exp in sorted(self.experiments.items()):
            if exp.get("verdict") not in DOWNGRADED:
                continue
            with self.subTest(finding_id=fid):
                ev = exp.get("two_revision_evidence") or {}
                self.assertIn(ev.get("status"), ("PARTIAL", "UNVERIFIABLE"))
                self.assertTrue(ev.get("missing_evidence"),
                                "a downgraded claim must name what is missing")

    def test_recorded_verdict_is_what_the_artefacts_support(self):
        """(c) The report may not claim more than the committed bytes show."""
        for fid, exp in sorted(self.experiments.items()):
            with self.subTest(finding_id=fid):
                self.assertEqual(exp.get("verdict"), expected_verdict(fid, exp),
                                 "the recorded verdict is not the verdict the "
                                 "committed artefacts support")

    def test_downgrade_is_reproduced_by_the_builder(self):
        """(c) Regenerating the report must not restore an over-stated verdict.

        The builder's own classifier is used when the audited repository is
        cloned here; a clean checkout cannot import it, and that is a visible
        skip rather than a silent pass.
        """
        try:
            sys.path.insert(0, str(ROOT / "scripts"))
            import run_verified_experiments as rve  # noqa: E402
        except BaseException as exc:  # SystemExit when the clone is absent
            self.skipTest(f"the builder cannot be imported here ({exc}); the "
                          "independent re-derivation above still applies")
        for fid, exp in sorted(self.experiments.items()):
            with self.subTest(finding_id=fid):
                status = rve.classify_two_revision_evidence(fid)
                self.assertEqual(exp.get("verdict"), expected_verdict(fid, exp))
                self.assertEqual(
                    (exp.get("two_revision_evidence") or {}).get("status"),
                    status.get("status"),
                    "the recorded evidence does not match the builder's "
                    "classification of the same artefacts")


class TestRecoveredRenftClaims(unittest.TestCase):
    """The two recovered claims assert the vulnerability, not just a red suite."""

    CASES = {
        "2024-01-renft/M-01": {
            "test": "test_VlunM01_NonRentedERC1155StaysTransferable()",
            "reason": "GuardPolicy_UnauthorizedSelector(0xf242432a)",
            "vulnerable_commit": "3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291",
            "fixed_commit": "45ef41123b65d67b7f83cad8bc9d35917b9da30f",
            "harness": "vlun_renft_m01_partial_transfer.t.sol",
        },
        "2024-01-renft/M-08": {
            "test": "test_VlunM08_RentedERC721CannotBeBurned()",
            "reason": "next call did not revert as expected",
            "vulnerable_commit": "3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291",
            "fixed_commit": "fb8013111b57c1e09482fb3193db58cb892229e9",
            "harness": "vlun_renft_m08_destructive_burn.t.sol",
        },
    }

    def setUp(self):
        self.report = load_report()
        self.experiments = {e["finding_id"]: e
                            for e in self.report.get("experiments", [])}

    def test_claim_is_l6_with_the_intended_assertion(self):
        for fid, want in self.CASES.items():
            with self.subTest(finding_id=fid):
                exp = self.experiments.get(fid)
                self.assertIsNotNone(exp, f"{fid} is missing from the report")
                self.assertEqual(exp.get("verdict"), VERIFIED)
                ev = exp.get("two_revision_evidence") or {}
                self.assertEqual(ev.get("status"), "VERIFIED_TWO_REVISION")
                self.assertEqual(ev.get("missing_evidence"), [])
                v = exp["revisions"]["vulnerable"]
                f = exp["revisions"]["fixed"]
                self.assertEqual(v["commit"], want["vulnerable_commit"])
                self.assertEqual(f["commit"], want["fixed_commit"])
                self.assertEqual(v["harness_digest"], f["harness_digest"])
                self.assertEqual(v["harness_file_digests"],
                                 f["harness_file_digests"])
                self.assertEqual(list(v["harness_file_digests"]),
                                 [want["harness"]],
                                 "exactly one published, byte-identical harness")
                self.assertEqual(v["production_files_modified"], 0)
                self.assertEqual(f["production_files_modified"], 0)
                self.assertEqual(v["per_test_status"],
                                 {want["test"]: "Failure"})
                self.assertEqual(f["per_test_status"],
                                 {want["test"]: "Success"})
                observed = v.get("observed_failure") or []
                self.assertEqual(len(observed), 1, observed)
                self.assertEqual(observed[0]["test"], want["test"])
                self.assertTrue(
                    (observed[0].get("forge_reason") or "").startswith(
                        want["reason"]),
                    f"the vulnerable run failed for another reason: "
                    f"{observed[0].get('forge_reason')!r}")


class TestL6ArtefactHashes(unittest.TestCase):
    """(b) An artefact hash that does not match the committed bytes has to be
    recorded as unresolved; it must never be a silent pass."""

    def _scan(self):
        mismatches, missing = [], []
        for label, base, pattern, key, scheme in rpa.LAYERS:
            if label not in ("v1 experiments", "v2.2 experiments",
                             "v2.2 index"):
                continue
            c, m, x = rpa.scan_layer(label, base, pattern, key, scheme)
            mismatches += m
            missing += x
        return mismatches, missing

    def test_no_missing_artefact(self):
        mismatches, missing = self._scan()
        self.assertEqual(missing, [], f"{len(missing)} artefact(s) claimed but absent")

    def test_every_mismatch_is_recorded_as_unresolved(self):
        mismatches, _ = self._scan()
        known = rpa.unresolved_index()
        unrecorded = [m for m in mismatches if m["path"] not in known]
        self.assertEqual(unrecorded, [],
                         f"{len(unrecorded)} artefact hash mismatch(es) are not "
                         "recorded as unresolved")
        for m in mismatches:
            entry = known[m["path"]]
            self.assertEqual(entry["recorded_sha256"], m["recorded_sha256"],
                             "the recorded value in the table is stale")
            self.assertEqual(entry["committed_sha256"], m["committed_sha256"],
                             "the committed value in the table is stale")
            self.assertTrue(entry.get("reason"),
                            "an unresolved mismatch must state the reason")

    def test_the_unresolved_table_has_no_rotted_entries(self):
        mismatches, _ = self._scan()
        seen = {m["path"] for m in mismatches}
        for path in rpa.unresolved_index():
            self.assertIn(path, seen,
                          f"{path} is listed as unresolved but its digest now "
                          "matches; the table has to be corrected")

    def test_report_artefact_digests_match_the_bytes(self):
        """The digests the L6 report carries are the committed bytes' digests."""
        report = load_report()
        for exp in report.get("experiments", []):
            fid = exp["finding_id"]
            for label in ("vulnerable", "fixed"):
                rec = (exp.get("revisions") or {}).get(label) or {}
                hashes = rec.get("artifact_hashes") or {}
                if not hashes:
                    continue
                with self.subTest(finding_id=fid, revision=label):
                    base = EXPERIMENTS / fid.replace("/", "__") / label
                    for name, meta in hashes.items():
                        self.assertEqual(meta.get("hash_version"),
                                         rpa.HASH_VERSION,
                                         "a newly computed digest must carry the "
                                         "scheme version")
                        f = base / name
                        self.assertTrue(f.is_file(), f"{name} is missing")
                        self.assertEqual(meta.get("sha256"),
                                         rpa.digest_normalised(f.read_bytes()),
                                         f"{name} does not match the committed bytes")

    def test_unresolved_mismatches_are_named_in_the_report(self):
        """An artefact whose recorded digest does not reproduce is named."""
        report = load_report()
        for exp in report.get("experiments", []):
            fid = exp["finding_id"]
            for label in ("vulnerable", "fixed"):
                rec = (exp.get("revisions") or {}).get(label) or {}
                named = {m.get("artefact"): m
                         for m in (rec.get("artifact_hash_mismatches") or [])}
                result = revision_result(fid, label)
                if result is None:
                    continue
                base = EXPERIMENTS / fid.replace("/", "__") / label
                for name, want in (result.get("artifact_sha256") or {}).items():
                    f = base / name
                    if not f.is_file():
                        continue
                    ok, _ = rpa.matches(want, f.read_bytes(), "sha256-v1-text")
                    with self.subTest(finding_id=fid, revision=label, artefact=name):
                        self.assertTrue(ok or name in named,
                                        "an artefact hash that does not match the "
                                        "committed bytes is not recorded as "
                                        "unresolved")


if __name__ == "__main__":
    unittest.main(verbosity=2)
