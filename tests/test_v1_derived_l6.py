"""V1 derived records must carry the L6 evidence the report actually holds.

`derived/records.jsonl` used to show the reNFT findings as
`not_executed` / `unknown` because `_verification_block` only looked at the
machine-local `work/poc_runs` index, which never runs a fixed revision. The
seven controlled two-revision results in `reports/verified_experiments.json`
were therefore invisible to the derived layer.

The merge is now a pure function (`build_derived.merge_verification`) so these
tests exercise every gate without rebuilding the 722-record layer:

  * a valid two-revision claim is emitted as L6 / VERIFIED_TWO_REVISION with
    `evidence_type: experimentally_verified` and compact commits/digest/test
    evidence;
  * a missing fixed commit, a digest mismatch, the same commit on both sides,
    a single-pass/no-fail run, a compile error or a timeout is rejected and the
    lower verification is kept with the reason;
  * a weaker prior PoC verdict (`not_executed`, `inconclusive`) is superseded
    and the conflict recorded; a stronger prior (`reproduced`) is kept;
  * findings without an authoritative experiment are byte-for-byte unchanged.

Run:  python -m unittest tests.test_v1_derived_l6
"""

from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import build_derived as bd  # noqa: E402

FINDING_ID = "2024-01-renft/H-01"
VULNERABLE_COMMIT = "3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291"
FIXED_COMMIT = "1783237cf05c9369c271b6f3a388b8d57d03ecc8"
HARNESS_DIGEST = ("820b68e8887c1a8bdb30b5b080dbfd7c"
                  "0736aec9577baa7f20e31c1e87d36375")
TEST_FILE = "integration__prevented-exploits__MaliciousSeaportTip.t.sol"
TEST_NAME = "test_MaliciousSeaportTip_Exploit()"

ACCEPTED_L6 = (
    "2024-01-renft/H-01",
    "2024-01-renft/H-03",
    "2024-01-renft/H-04",
    "2024-01-renft/M-01",
    "2024-01-renft/M-08",
    "2024-01-renft/M-09",
    "2024-01-renft/M-11",
)
INCONCLUSIVE = ("2024-01-renft/H-06", "2024-01-renft/M-02")


def valid_experiment() -> dict:
    """One well-formed two-revision experiment, shaped like the real report."""
    side = {
        "harness_digest": HARNESS_DIGEST,
        "harness_file_digests": {TEST_FILE: "aa" * 32},
        "per_test_status": {TEST_NAME: "Failure"},
    }
    return {
        "finding_id": FINDING_ID,
        "verdict": "l6_verified_patch",
        "classification": "runnable_after_harness_reconstruction",
        "evidence_layer": "dynamic_poc_plus_source_diff",
        "controlled_comparison": True,
        "revisions": {
            "vulnerable": {
                **copy.deepcopy(side),
                "commit": VULNERABLE_COMMIT,
                "status": "fail",
                "declared_expected_status": "fail",
            },
            "fixed": {
                **copy.deepcopy(side),
                "commit": FIXED_COMMIT,
                "status": "pass",
                "declared_expected_status": "pass",
                "per_test_status": {TEST_NAME: "Success"},
            },
        },
        "two_revision_evidence": {
            "status": "VERIFIED_TWO_REVISION",
            "missing_evidence": [],
            "harness_digests_match": True,
            "test_file_digests_match": True,
            "test_files": [TEST_FILE],
            "commit_resolution": {
                "repository": "renft-smart",
                "status": "resolved",
                "resolved": [VULNERABLE_COMMIT, FIXED_COMMIT],
                "unresolved": [],
            },
        },
    }


NOT_EXECUTED = {
    "verdict": "not_executed",
    "failure_reason": "poc_invalid",
    "poc_type": "not_a_runnable_test",
    "evidence": {},
}


def prior_block() -> dict:
    return bd._prior_verification_block(NOT_EXECUTED)


class TestAuthoritativeL6Gates(unittest.TestCase):
    def test_valid_l6_mapped(self):
        block = bd.merge_verification(None, valid_experiment(), FINDING_ID)
        self.assertEqual(block["level"], "L6")
        self.assertEqual(block["status"], "VERIFIED_TWO_REVISION")
        self.assertEqual(block["verdict"], "l6_verified_patch")
        self.assertEqual(block["evidence_type"], "experimentally_verified")
        self.assertTrue(block["attempted"])
        ev = block["evidence"]
        self.assertEqual(ev["commits"],
                         {"vulnerable": VULNERABLE_COMMIT,
                          "fixed": FIXED_COMMIT})
        self.assertEqual(ev["harness_digest"], HARNESS_DIGEST)
        self.assertEqual(ev["test_files"], [TEST_FILE])
        self.assertEqual(ev["tests"],
                         {TEST_NAME: {"vulnerable": "fail", "fixed": "pass"}})
        self.assertNotIn("l6_rejected", block)

    def test_missing_fixed_commit_rejected(self):
        exp = valid_experiment()
        exp["revisions"]["fixed"].pop("commit")
        claim = bd.evaluate_l6_claim(FINDING_ID, exp)
        self.assertFalse(claim["accepted"])
        self.assertTrue(any("fixed revision" in r for r in claim["reasons"]),
                        claim["reasons"])
        block = bd.merge_verification(NOT_EXECUTED, exp, FINDING_ID)
        self.assertNotEqual(block.get("level"), "L6")
        self.assertIn("l6_rejected", block)
        self.assertTrue(block["l6_rejected"]["reasons"])

    def test_digest_mismatch_rejected(self):
        exp = valid_experiment()
        exp["two_revision_evidence"]["harness_digests_match"] = False
        exp["revisions"]["fixed"]["harness_digest"] = "bb" * 32
        claim = bd.evaluate_l6_claim(FINDING_ID, exp)
        self.assertFalse(claim["accepted"])
        self.assertTrue(any("harness" in r for r in claim["reasons"]),
                        claim["reasons"])

        exp = valid_experiment()
        exp["two_revision_evidence"]["test_file_digests_match"] = False
        claim = bd.evaluate_l6_claim(FINDING_ID, exp)
        self.assertFalse(claim["accepted"])
        self.assertTrue(any("test file" in r for r in claim["reasons"]),
                        claim["reasons"])

    def test_same_commit_rejected(self):
        exp = valid_experiment()
        exp["revisions"]["fixed"]["commit"] = VULNERABLE_COMMIT
        exp["two_revision_evidence"]["commit_resolution"]["resolved"] = [
            VULNERABLE_COMMIT]
        claim = bd.evaluate_l6_claim(FINDING_ID, exp)
        self.assertFalse(claim["accepted"])
        self.assertTrue(any("same commit" in r for r in claim["reasons"]),
                        claim["reasons"])

    def test_single_pass_no_fail_rejected(self):
        exp = valid_experiment()
        exp["revisions"]["vulnerable"]["status"] = "pass"
        exp["revisions"]["vulnerable"]["declared_expected_status"] = "pass"
        exp["revisions"]["fixed"]["status"] = "pass"
        exp["revisions"]["fixed"]["declared_expected_status"] = "pass"
        claim = bd.evaluate_l6_claim(FINDING_ID, exp)
        self.assertFalse(claim["accepted"])
        self.assertTrue(any("polarity" in r for r in claim["reasons"]),
                        claim["reasons"])

    def test_reversed_polarity_rejected(self):
        exp = valid_experiment()
        exp["revisions"]["vulnerable"]["status"] = "pass"
        exp["revisions"]["vulnerable"]["declared_expected_status"] = "pass"
        exp["revisions"]["fixed"]["status"] = "fail"
        exp["revisions"]["fixed"]["declared_expected_status"] = "fail"
        claim = bd.evaluate_l6_claim(FINDING_ID, exp)
        self.assertFalse(claim["accepted"])
        self.assertTrue(any("polarity" in r for r in claim["reasons"]),
                        claim["reasons"])

    def test_compile_error_rejected(self):
        exp = valid_experiment()
        exp["revisions"]["vulnerable"]["status"] = "compile_error"
        exp["revisions"]["vulnerable"]["per_test_status"] = {}
        claim = bd.evaluate_l6_claim(FINDING_ID, exp)
        self.assertFalse(claim["accepted"])
        self.assertTrue(any("compile_error" in r for r in claim["reasons"]),
                        claim["reasons"])

    def test_report_verdict_alone_is_not_enough(self):
        exp = valid_experiment()
        exp["two_revision_evidence"] = {"status": "UNVERIFIABLE",
                                        "missing_evidence": ["no artefacts"]}
        claim = bd.evaluate_l6_claim(FINDING_ID, exp)
        self.assertFalse(claim["accepted"])


class TestMergeWithPriorEvidence(unittest.TestCase):
    def test_conflict_recorded(self):
        block = bd.merge_verification(NOT_EXECUTED, valid_experiment(),
                                      FINDING_ID)
        self.assertEqual(block["level"], "L6")
        conflict = block["evidence_conflict"]
        self.assertEqual(conflict["prior"]["source"], "work/poc_runs")
        self.assertEqual(conflict["prior"]["verdict"], "not_executed")
        self.assertEqual(conflict["new"]["source"],
                         "reports/verified_experiments.json")
        self.assertEqual(conflict["new"]["level"], "L6")
        self.assertEqual(conflict["resolution"], "authoritative_l6_kept")
        self.assertEqual(block["prior_verdict"], "not_executed")

    def test_prior_l5_reproduced_is_kept(self):
        prior = {"verdict": "reproduced", "poc_type": "report_quoted_poc",
                 "evidence": {"forge_status": "pass"}}
        block = bd.merge_verification(prior, valid_experiment(), FINDING_ID)
        self.assertNotIn("level", block)
        self.assertEqual(block["verdict"], "reproduced")
        self.assertEqual(block["evidence_conflict"]["resolution"], "prior_kept")
        self.assertEqual(block["evidence_conflict"]["prior"]["verdict"],
                         "reproduced")

    def test_inconclusive_stays_lower(self):
        exp = valid_experiment()
        exp["verdict"] = "inconclusive"
        exp["two_revision_evidence"]["status"] = "UNVERIFIABLE"
        exp["two_revision_evidence"]["missing_evidence"] = ["compile error"]
        block = bd.merge_verification(NOT_EXECUTED, exp, FINDING_ID)
        self.assertEqual(block, prior_block())
        self.assertNotIn("level", block)

        empty = bd.merge_verification(None, exp, FINDING_ID)
        self.assertEqual(empty, bd._prior_verification_block(None))

    def test_non_renft_unaffected(self):
        prior = {"verdict": "reproduced", "poc_type": "report_quoted_poc",
                 "evidence": {"forge_status": "pass"}}
        expected = {
            "attempted": True,
            "verdict": "reproduced",
            "failure_reason": None,
            "poc_type": "report_quoted_poc",
            "evidence_type": "experimentally_verified",
            "test_evidence": {"forge_status": "pass"},
        }
        self.assertEqual(
            bd.merge_verification(prior, None, "2024-04-noya/H-01"), expected)
        self.assertEqual(
            bd.merge_verification(None, None, "2024-04-noya/H-01"),
            bd._prior_verification_block(None))


class TestCommittedReport(unittest.TestCase):
    """The real report yields exactly the seven accepted L6 claims."""

    def setUp(self):
        self.authoritative = bd.load_authoritative_verification()

    def test_report_maps_exactly_seven_l6(self):
        accepted = sorted(fid for fid, exp in self.authoritative.items()
                          if bd.evaluate_l6_claim(fid, exp)["accepted"])
        self.assertEqual(accepted, sorted(ACCEPTED_L6))

    def test_inconclusive_findings_keep_the_lower_block(self):
        for fid in INCONCLUSIVE:
            with self.subTest(finding_id=fid):
                block = bd.merge_verification(
                    NOT_EXECUTED, self.authoritative[fid], fid)
                self.assertEqual(block, prior_block())
                self.assertNotIn("level", block)


class TestPublishedLayerSurvives(unittest.TestCase):
    """The rebuild must not delete execution findings it cannot re-derive.

    `work/poc_runs/` is git-ignored and absent here, and `V1/clones/` is absent
    too, so a full rebuild of `derived/records.jsonl` would both drop the 155
    published single-revision verdicts and rewrite 390 records' code-context,
    licence and redistribution fields for reasons that have nothing to do with
    L6. These tests pin the two protections: the committed layer is read back as
    the verdict index, and the in-place merge touches only the verification
    block and the derived flag it feeds.
    """

    @classmethod
    def setUpClass(cls):
        import json
        cls.records = [json.loads(line) for line in
                       (ROOT / "derived" / "records.jsonl")
                       .read_text(encoding="utf-8").splitlines() if line.strip()]
        cls.by_id = {r["id"]: r for r in cls.records}
        cls.priors = bd.load_committed_verification()
        cls.authoritative = bd.load_authoritative_verification()

    def _fid(self, rec):
        return (rec.get("finding") or {}).get("id") or rec["id"]

    def test_committed_index_recovers_every_published_verdict(self):
        published = {self._fid(r): r["verification"] for r in self.records
                     if r.get("verification", {}).get("attempted")}
        # 155 records carried a single-revision verdict before the merge; seven
        # now carry an L6 block, five of those alongside their prior verdict and
        # two with no prior at all, so 157 blocks are `attempted` and 155
        # verdicts must still be recoverable.
        self.assertEqual(len(published), 157)
        recoverable = {fid for fid, ver in published.items()
                       if ver.get("prior_verdict")
                       or (ver.get("verdict")
                           and ver.get("verdict") != "l6_verified_patch")}
        self.assertEqual(len(recoverable), 155)
        self.assertEqual(set(self.priors), recoverable)
        for fid, ver in published.items():
            want = ver.get("prior_verdict") if ver.get("level") == "L6" else ver.get("verdict")
            if want is None:
                self.assertNotIn(fid, self.priors, fid)
                continue
            got = self.priors[fid]
            self.assertEqual(got["verdict"], want, fid)
            self.assertEqual(got["poc_type"],
                             (ver.get("evidence_conflict") or {}).get("prior", {}).get(
                                 "poc_type", ver.get("poc_type")), fid)

    def test_surgical_merge_changes_only_the_two_verification_fields(self):
        import json
        for rec in self.records:
            fid = self._fid(rec)
            if fid not in self.authoritative:
                continue
            before = json.dumps(rec, sort_keys=True)
            changed = bd.derive_l6_record(rec, self.priors.get(fid),
                                          self.authoritative[fid])
            after = json.dumps(rec, sort_keys=True)
            if changed:
                diff = [k for k in rec
                        if json.dumps(json.loads(before)[k], sort_keys=True)
                        != json.dumps(rec[k], sort_keys=True)]
                self.assertEqual(sorted(diff), sorted(bd.L6_SURGICAL_FIELDS),
                                 f"{fid} touched {diff}")

    def test_surgical_merge_emits_exactly_seven_l6(self):
        levels = [(r.get("verification") or {}).get("level") for r in self.records]
        self.assertEqual(levels.count("L6"), 7)
        self.assertEqual(sorted(self._fid(r) for r in self.records
                                if (r.get("verification") or {}).get("level") == "L6"),
                         sorted(ACCEPTED_L6))

    def test_prior_verdict_is_kept_beside_every_promoted_l6(self):
        promoted = [r for r in self.records
                    if (r.get("verification") or {}).get("level") == "L6"]
        with_prior = [r for r in promoted
                      if (r["verification"] or {}).get("prior_verdict")]
        self.assertEqual(len(with_prior), 5, "the five records with a published "
                        "single-revision verdict must state it alongside the L6 block")
        for r in with_prior:
            ver = r["verification"]
            conflict = ver["evidence_conflict"]
            self.assertEqual(conflict["resolution"], "authoritative_l6_kept")
            self.assertEqual(conflict["prior"]["verdict"], ver["prior_verdict"])
            self.assertEqual(ver["status"], "VERIFIED_TWO_REVISION")
            self.assertEqual(ver["evidence"]["source"],
                             "reports/verified_experiments.json")

    def test_l6_block_round_trips_back_into_the_prior_index(self):
        """A second rebuild reads the same prior, so the layer is stable."""
        import json
        for r in self.records:
            ver = r.get("verification") or {}
            if ver.get("level") != "L6":
                continue
            fid = self._fid(r)
            recovered = self.priors.get(fid)
            want = ver.get("prior_verdict")
            if want is None:
                self.assertIsNone(recovered, fid)
                continue
            self.assertEqual(recovered["verdict"], want, fid)
            self.assertEqual(json.dumps(
                bd.merge_verification(recovered, self.authoritative[fid], fid),
                sort_keys=True), json.dumps(ver, sort_keys=True), fid)

    def test_without_the_committed_fallback_verdicts_would_be_lost(self):
        """Documents why load_committed_verification exists."""
        import json
        rec = self.by_id["2024-01-renft/M-11"]
        block = bd.merge_verification(None, None, "2024-01-renft/M-11")
        self.assertFalse(block["attempted"])
        self.assertNotEqual(json.dumps(block, sort_keys=True),
                            json.dumps(rec["verification"], sort_keys=True))

    def test_l6_claims_are_backed_by_committed_run_artefacts(self):
        """The critical gate's own rule, asserted here at the source."""
        import json
        idx = json.loads((ROOT / "reports" / "run_artefacts_index.json")
                         .read_text(encoding="utf-8"))["records"]
        for fid in ACCEPTED_L6:
            self.assertIn(fid, idx, fid)
            entry = idx[fid]
            self.assertTrue(entry.get("two_revision"), fid)
            for key in ("artefact", "artefacts_fixed"):
                self.assertTrue((ROOT / entry[key]).is_file(),
                                f"{fid}: {entry[key]}")


if __name__ == "__main__":
    unittest.main(verbosity=2)