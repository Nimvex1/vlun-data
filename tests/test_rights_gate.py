#!/usr/bin/env python3
"""Tests for scripts/check_rights_consistency.py (spec item 5 rights gate).

Each broken fixture under tests/fixtures/broken/ must make the gate exit
non-zero AND report the specific reason code it is designed to catch; a
fixture that only produces unrelated noise would pass this test silently, so
both the exit code and the code are asserted.

The good fixture under tests/fixtures/good/ is the reconciled shape of the
same inputs: it must exit 0, which proves the checks are not vacuous.

The release-manifest tests build a small tree, generate its manifest with
scripts/build_release_manifest.py, then break one thing at a time and assert
that the gate names that thing:

  * a shipped rights statement that contradicts the actual manifest
    (a licence that grants a withheld path; a status that contradicts the
    file's content);
  * a path the manifest releases that is missing, and a file in the tree that
    the manifest does not classify;
  * a manifest that no longer matches what the builder computes.

Run:  python -m unittest tests.test_rights_gate
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

from vlun_io import read_jsonl  # noqa: E402

GATE = ROOT / "scripts" / "check_rights_consistency.py"
BUILDER = ROOT / "scripts" / "build_release_manifest.py"
BROKEN = ROOT / "tests" / "fixtures" / "broken"
GOOD = ROOT / "tests" / "fixtures" / "good"

# A sentence long enough to be a verbatim third-party run (> 200 characters,
# so a file that carries it is withheld, not merely quoted).
COPIED = (
    "The withdrawn contract lets any caller drain the vault without checking "
    "the owner gate that the auditor described in the published finding, and "
    "the published remediation advice did not mention the missing check at "
    "all, so the text is carried here to prove the detector can see it."
)
# Verbatim third-party SOURCE CODE.  The project's own policy never carries
# third-party code, not even a short quotation of it.
COPIED_CODE = (
    "contract Vault is Ownable { function withdraw() external onlyOwner { "
    "(bool ok, ) = msg.sender.call{value: address(this).balance}(\"\"); "
    "require(ok); } }"
)


def run_gate(fixture: Path) -> tuple[int, dict]:
    proc = subprocess.run(
        [sys.executable, str(GATE), "--root", str(fixture), "--partial",
         "--quiet", "--json"],
        capture_output=True, text=True, encoding="utf-8", errors="replace")
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        raise AssertionError(
            f"gate printed no JSON for {fixture}\n"
            f"stdout={proc.stdout[:500]!r}\nstderr={proc.stderr[:900]!r}")
    return proc.returncode, payload


def codes(payload: dict) -> set[str]:
    return {r["code"] for r in payload.get("reasons", [])}


class V4StatusesAreReconciled(unittest.TestCase):
    """The layers must state one licence status per source."""

    def test_sources_records_and_registry_agree(self) -> None:
        decision = {s["source_id"]: s["license_status"] for s in
                    json.loads((ROOT / "V4" / "licensing.json")
                               .read_text(encoding="utf-8"))["sources"]}
        sources = {r["source_id"]: r["license_status"] for r in
                   json.loads((ROOT / "V4" / "sources.json").read_text(encoding="utf-8"))}
        self.assertEqual(sources, decision)
        registry = {r["source_id"]: r["license_status_required"] for r in
                    json.loads((ROOT / "distribution_v1" / "rights_source_registry.json")
                               .read_text(encoding="utf-8"))["sources"]}
        self.assertEqual({k: registry[k] for k in decision}, decision)
        per_record = set()
        for row in read_jsonl(ROOT / "jsonl_v4" / "findings.jsonl"):
            per_record.add((row["source_id"], row["license_status"]))
        self.assertEqual({sid for sid, _ in per_record}, set(decision))
        for sid, status in per_record:
            self.assertEqual(status, decision[sid], sid)
        self.assertTrue(all("status_drift_in_published_records" not in r or
                            not r["status_drift_in_published_records"]
                            for r in json.loads((ROOT / "distribution_v1"
                                                / "rights_source_registry.json")
                                               .read_text(encoding="utf-8"))["sources"]))

    def test_no_source_ships_a_placeholder_status(self) -> None:
        for row in read_jsonl(ROOT / "jsonl_v4" / "findings.jsonl"):
            self.assertNotEqual(row.get("license"), "unknown", row.get("record_id"))
            self.assertNotEqual(row.get("license_status"), "unknown")
            self.assertIn("rights_decision", row)


class RightsGateBrokenFixtures(unittest.TestCase):
    def test_copied_unlicensed_source_fails(self) -> None:
        code, payload = run_gate(BROKEN / "copied_unlicensed_source")
        self.assertEqual(code, 1, payload)
        self.assertIn("DIST_FORBIDDEN_CODE_PRESENT", codes(payload))

    def test_two_licence_statuses_for_one_source_fails(self) -> None:
        code, payload = run_gate(BROKEN / "contradictory_licence")
        self.assertEqual(code, 1, payload)
        self.assertIn("LICENCE_STATUS_CONTRADICTION", codes(payload))
        self.assertIn("UNKNOWN_MASKS_DECLARED_LICENCE", codes(payload))
        oak = [r for r in payload["reasons"]
               if r.get("source_id") == "oak_security_audit_reports"]
        self.assertTrue(oak, "the Oak Security CC BY-ND case must be named")

    def test_attribution_free_digest_fails(self) -> None:
        code, payload = run_gate(BROKEN / "attribution_free_digest")
        self.assertEqual(code, 1, payload)
        self.assertIn("DIGEST_MISSING_ATTRIBUTION", codes(payload))

    def test_bad_hash_fails(self) -> None:
        code, payload = run_gate(BROKEN / "bad_hash")
        self.assertEqual(code, 1, payload)
        self.assertIn("INVALID_SHA256", codes(payload))
        self.assertIn("MANIFEST_HASH_MISMATCH", codes(payload))

    def test_an_abbreviated_commit_may_not_be_filed_as_immutable(self) -> None:
        """A 7-character prefix is what a report stated, not a pin."""
        code, payload = run_gate(BROKEN / "abbrev_commit_as_immutable")
        self.assertEqual(code, 1, payload)
        self.assertIn("INVALID_COMMIT_REF", codes(payload))
        row = next(json.loads(ln) for ln in (BROKEN / "abbrev_commit_as_immutable" /
                                              "distribution_v1" /
                                              "records_v1_withheld_pointers.jsonl")
                   .read_text(encoding="utf-8").splitlines() if ln.strip())
        self.assertEqual(row["immutable_reference"]["vulnerable_commit"], "64d3a2d")
        # and the projection this repo actually ships keeps them apart
        live = next(json.loads(ln) for ln in
                    (ROOT / "distribution_v1" / "records_v4_withheld_pointers.jsonl")
                    .read_text(encoding="utf-8").splitlines() if ln.strip())
        for key, value in (live.get("immutable_reference") or {}).items():
            self.assertRegex(str(value), r"^[0-9a-f]{40}$", key)
        self.assertNotIn("64d3a2d", json.dumps(live.get("immutable_reference") or {}))

    def test_reasons_are_machine_readable(self) -> None:
        _code, payload = run_gate(BROKEN / "copied_unlicensed_source")
        self.assertEqual(payload["exit_code"], 1)
        self.assertTrue(payload["reasons"])
        for r in payload["reasons"]:
            self.assertIn("code", r)
            self.assertIn("artifact", r)
            self.assertIn("detail", r)
        self.assertTrue(payload["policy_is_default_not_clearance"])
        self.assertEqual(payload["rights_transformation_version"], "rights-1.0")


class RightsGateGoodFixture(unittest.TestCase):
    def test_reconciled_fixture_passes(self) -> None:
        code, payload = run_gate(GOOD)
        self.assertEqual(code, 0, json.dumps(payload, indent=2)[:2000])
        self.assertEqual(payload["reasons"], [])


# ---------------------------------------------------------------------------
# the release manifest
# ---------------------------------------------------------------------------

def build_fixture(root: Path, open_question_ids: list[str]) -> None:
    """A small, self-consistent tree with one copied third-party passage.

    ``open_question_ids`` are the cases that need human legal review and
    that the release manifest declares for this tree; the notice lists
    exactly those, because the rights gate requires the notice and the
    manifest to declare the same set.
    """
    (root / "derived").mkdir(parents=True, exist_ok=True)
    (root / "reports").mkdir(parents=True, exist_ok=True)
    (root / "scripts").mkdir(parents=True, exist_ok=True)
    # the canonical third-party corpus layer: one code_context snippet
    (root / "derived" / "records.jsonl").write_text(
        json.dumps({"id": "2024-01-example/H-01",
                    "code_context": [{"snippet": COPIED,
                                      "file": "src/Vault.sol"},
                                     {"snippet": COPIED_CODE,
                                      "file": "src/Code.sol"}]},
                   sort_keys=True) + "\n",
        encoding="utf-8", newline="\n")
    # a report that carries the same bytes
    (root / "reports" / "example.json").write_text(
        json.dumps({"note": COPIED}, sort_keys=True) + "\n",
        encoding="utf-8", newline="\n")
    # a report that carries the same third-party SOURCE CODE
    (root / "reports" / "code.json").write_text(
        json.dumps({"note": COPIED_CODE}, sort_keys=True) + "\n",
        encoding="utf-8", newline="\n")
    (root / "scripts" / "run.py").write_text(
        "print('the authors own this')\n", encoding="utf-8", newline="\n")
    (root / "LICENSE").write_text(LICENCE_TEXT, encoding="utf-8", newline="\n")
    (root / "NOTICE.md").write_text(
        "NOTICE\n\nAttribution is not a redistribution right.\n\n"
        "- example_public_reports: an upstream report collection\n"
        "- code4rena/2024-04-noya: an audited protocol repository\n\n"
        + "".join(OPEN_QUESTION_LINE.format(oid=oid)
                  for oid in open_question_ids),
        encoding="utf-8", newline="\n")
    (root / "publish_manifest.json").write_text(
        json.dumps({
            "release_manifest": "RELEASE_MANIFEST.json",
            "release_manifest_version": "release-1.0",
            "covers_third_party_material": False,
            "legal_clearance_claimed": False,
            "attribution_is_not_a_right_grant": True,
            "hash_or_url_is_not_a_right_grant": True,
            "not_a_legal_clearance": True,
            "licences_of_released_paths": {"code": "MIT", "data": "CC-BY-4.0"},
        }, indent=2, sort_keys=True) + "\n",
        encoding="utf-8", newline="\n")
    # the machine-readable attribution table the notice must match
    (root / "distribution_v1").mkdir(parents=True, exist_ok=True)
    (root / "distribution_v1" / "rights_source_registry.json").write_text(
        json.dumps({
            "registry_version": "rights-1.0",
            "data_handling_policy_default": "METADATA_ONLY",
            "sources": [
                {"source_id": "example_public_reports",
                 "legal_clearance": False,
                 "redistribution_right": "not_documented"},
                {"source_id": "code4rena/2024-04-noya",
                 "legal_clearance": False,
                 "redistribution_right": "not_documented"},
            ],
        }, indent=2, sort_keys=True) + "\n",
        encoding="utf-8", newline="\n")


OPEN_QUESTION_LINE = "- {oid}: needs human legal review.\n"

LICENCE_TEXT = """VLUN fixture licence

0. WHAT IS LICENSED HERE AT ALL

This licence covers ONLY the material the VLUN authors authored, and ONLY the
part of that material that is released. The released set is enumerated, path
by path, in `RELEASE_MANIFEST.json`. A path that is not listed there with a
released rights status is not licensed here.

1. THE RELEASED DATA AND DOCUMENTATION - CC BY 4.0

The Creative Commons Attribution 4.0 International licence (CC BY 4.0) covers
the material the VLUN authors authored inside the released set.

SPDX-License-Identifier: CC-BY-4.0

This grant does not cover copied third-party source text, proof-of-concept
code, third-party report prose or personal data, wherever it occurs.

2. THE PIPELINE - MIT

Everything under `scripts/` is licensed under the MIT licence.

SPDX-License-Identifier: MIT

3. THIRD-PARTY SOURCE - NOT LICENSED HERE

The dataset quotes source from repositories whose terms this project does not
own. This licence does not grant you any right to that source, and it cannot.

4. ATTRIBUTION

Attribution is not a redistribution right. Naming an author identifies whose
work it is; it does not license it.
"""


def generate_manifest(root: Path) -> list[str]:
    """Run the builder over the tree and return the open questions it declares."""
    proc = subprocess.run(
        [sys.executable, str(BUILDER), "--root", str(root)],
        capture_output=True, text=True, encoding="utf-8", errors="replace")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    manifest = json.loads(
        (root / "RELEASE_MANIFEST.json").read_text(encoding="utf-8"))
    return [q["id"] for q in manifest["open_questions"]]


def make_tree() -> Path:
    """Build the fixture tree and generate its release manifest.

    Which open questions the manifest declares is a property of the TREE,
    not a constant of the fixture.  The builder closes a case once the
    contradiction it describes is gone: OQ-006 (the blanket-licence case
    over README.md, docs/DATASHEET.md, CITATION.cff and .zenodo.json) is
    declared only while one of those four documents really still
    over-grants, and this fixture contains none of them, so the builder
    closes it.  The notice therefore lists the ids that the generated
    manifest declares -- read back from that manifest, then re-generated so
    the tree and the manifest agree -- instead of a hard-coded range.  A
    hard-coded list goes stale the moment the builder's rule changes and
    would then fail the gate for a reason that has nothing to do with what
    this fixture is testing.
    """
    tmp = Path(tempfile.mkdtemp(prefix="vlun-rights-"))
    build_fixture(tmp, open_question_ids=[])
    declared = generate_manifest(tmp)
    assert declared, (
        "the builder must declare at least one open question for this tree; "
        "if that rule changed, the fixture's notice has to list something "
        "for the gate's NOTICE_MISSING_OPEN_QUESTIONS check")
    build_fixture(tmp, open_question_ids=declared)
    again = generate_manifest(tmp)
    assert again == declared, (
        "the fixture's open questions must converge: "
        f"{declared} then {again}")
    return tmp


def gate_on(root: Path) -> tuple[int, dict]:
    proc = subprocess.run(
        [sys.executable, str(GATE), "--root", str(root), "--partial",
         "--quiet", "--json"],
        capture_output=True, text=True, encoding="utf-8", errors="replace")
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        raise AssertionError(
            f"gate printed no JSON for {root}\n"
            f"stdout={proc.stdout[:800]!r}\nstderr={proc.stderr[:900]!r}")
    return proc.returncode, payload


def write_manifest(root: Path, manifest: dict) -> None:
    (root / "RELEASE_MANIFEST.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8", newline="\n")


class ReleaseManifestGate(unittest.TestCase):
    """The manifest, the licence and the content must agree."""

    def setUp(self) -> None:
        self.root = make_tree()
        self.addCleanup(shutil.rmtree, self.root, True)
        self.manifest = json.loads(
            (self.root / "RELEASE_MANIFEST.json").read_text(encoding="utf-8"))

    def test_the_generated_tree_passes(self) -> None:
        code, payload = gate_on(self.root)
        self.assertEqual(code, 0, json.dumps(payload, indent=2)[:3000])

    def test_manifest_marks_the_copied_file_as_withheld(self) -> None:
        self.assertEqual(
            self.manifest["paths"]["reports/example.json"],
            "withheld_third_party_no_redistribution_rights")

    def test_manifest_withholds_a_file_that_carries_third_party_code(self) -> None:
        """A short quotation of third-party code is still a copy of code."""
        self.assertEqual(
            self.manifest["paths"]["reports/code.json"],
            "withheld_third_party_no_redistribution_rights")

    def test_a_notice_that_drops_an_attribution_row_fails(self) -> None:
        notice = (self.root / "NOTICE.md").read_text(encoding="utf-8")
        notice = notice.replace(
            "- code4rena/2024-04-noya: an audited protocol repository\n", "")
        (self.root / "NOTICE.md").write_text(notice, encoding="utf-8",
                                            newline="\n")
        code, payload = gate_on(self.root)
        self.assertEqual(code, 1, json.dumps(payload, indent=2)[:2000])
        self.assertIn("NOTICE_ATTRIBUTION_MISSING", codes(payload))

    def test_a_licence_that_grants_a_withheld_path_fails(self) -> None:
        licence = (self.root / "LICENSE").read_text(encoding="utf-8")
        licence = licence.replace(
            "the material the VLUN authors authored inside the released set.",
            "the material the VLUN authors authored inside the released set, "
            "including the released paths under `reports/`.")
        (self.root / "LICENSE").write_text(licence, encoding="utf-8",
                                           newline="\n")
        code, payload = gate_on(self.root)
        self.assertEqual(code, 1, json.dumps(payload, indent=2)[:2000])
        self.assertIn("LICENCE_GRANTS_OVER_WITHHELD_PATH", codes(payload))

    def test_a_status_that_contradicts_the_content_fails(self) -> None:
        manifest = dict(self.manifest)
        paths = dict(manifest["paths"])
        paths["reports/example.json"] = "metadata_only"
        manifest["paths"] = paths
        write_manifest(self.root, manifest)
        code, payload = gate_on(self.root)
        self.assertEqual(code, 1, json.dumps(payload, indent=2)[:2000])
        self.assertIn("RELEASED_PATH_STATUS_CONTRADICTION", codes(payload))
        self.assertIn("RELEASED_PATH_CONTAINS_COPIED_CONTENT", codes(payload))

    def test_a_released_path_that_is_missing_fails(self) -> None:
        manifest = dict(self.manifest)
        paths = dict(manifest["paths"])
        paths["reports/not-in-the-tree.json"] = "project_own"
        manifest["paths"] = paths
        write_manifest(self.root, manifest)
        code, payload = gate_on(self.root)
        self.assertEqual(code, 1, json.dumps(payload, indent=2)[:2000])
        self.assertIn("RELEASE_PATH_MISSING", codes(payload))

    def test_a_tree_path_the_manifest_does_not_classify_fails(self) -> None:
        (self.root / "reports" / "unclassified.json").write_text(
            "{}\n", encoding="utf-8", newline="\n")
        code, payload = gate_on(self.root)
        self.assertEqual(code, 1, json.dumps(payload, indent=2)[:2000])
        self.assertIn("RELEASE_PATH_UNCLASSIFIED", codes(payload))

    def test_a_manifest_that_is_not_reproducible_fails(self) -> None:
        manifest = dict(self.manifest)
        manifest["counts"] = dict(manifest["counts"])
        manifest["counts"]["released_paths"] = 999
        write_manifest(self.root, manifest)
        code, payload = gate_on(self.root)
        self.assertEqual(code, 1, json.dumps(payload, indent=2)[:2000])
        self.assertIn("RELEASE_MANIFEST_NOT_REPRODUCIBLE", codes(payload))

    def test_the_builders_check_mode_fails_on_a_drifted_manifest(self) -> None:
        manifest = dict(self.manifest)
        manifest["counts"] = dict(manifest["counts"])
        manifest["counts"]["released_paths"] = 999
        write_manifest(self.root, manifest)
        proc = subprocess.run(
            [sys.executable, str(BUILDER), "--root", str(self.root), "--check"],
            capture_output=True, text=True, encoding="utf-8", errors="replace")
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("not reproducible", proc.stdout + proc.stderr)

    def test_the_builders_check_mode_passes_on_the_generated_manifest(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(BUILDER), "--root", str(self.root), "--check"],
            capture_output=True, text=True, encoding="utf-8", errors="replace")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_a_notice_that_drops_an_open_question_fails(self) -> None:
        # drop one of the open questions the manifest really declares, so
        # the fixture stays valid however the builder's rule changes
        declared = [q["id"] for q in self.manifest["open_questions"]]
        self.assertTrue(declared, "the fixture must declare an open question")
        oid = declared[0]
        notice = (self.root / "NOTICE.md").read_text(encoding="utf-8")
        line = OPEN_QUESTION_LINE.format(oid=oid)
        self.assertIn(line, notice, f"{oid} must be listed in the notice")
        notice = notice.replace(line, "")
        (self.root / "NOTICE.md").write_text(notice, encoding="utf-8",
                                             newline="\n")
        code, payload = gate_on(self.root)
        self.assertEqual(code, 1, json.dumps(payload, indent=2)[:2000])
        self.assertIn("NOTICE_OPEN_QUESTION_MISSING", codes(payload))

    def test_a_licence_that_drops_the_attribution_warning_fails(self) -> None:
        licence = (self.root / "LICENSE").read_text(encoding="utf-8")
        licence = licence.replace(
            "Attribution is not a redistribution right.", "Attribution applies.")
        (self.root / "LICENSE").write_text(licence, encoding="utf-8",
                                           newline="\n")
        code, payload = gate_on(self.root)
        self.assertEqual(code, 1, json.dumps(payload, indent=2)[:2000])
        self.assertIn("LICENCE_MISSING_ATTRIBUTION_NOT_A_GRANT", codes(payload))


class LiveReleaseManifest(unittest.TestCase):
    """Read-only checks against the real repository."""

    def test_the_committed_manifest_is_reproducible(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(BUILDER), "--check", "--quiet"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            cwd=str(ROOT))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_every_path_carries_a_status_and_a_licence(self) -> None:
        manifest = json.loads(
            (ROOT / "RELEASE_MANIFEST.json").read_text(encoding="utf-8"))
        for path, status in manifest["paths"].items():
            self.assertIn(status, manifest["statuses"], path)
            self.assertTrue((ROOT / path).is_file(), path)
            if status in ("project_own", "metadata_only", "attribution_required"):
                self.assertIn(path, manifest["path_licences"], path)
            else:
                self.assertNotIn(path, manifest["path_licences"], path)

    def test_the_licence_does_not_grant_a_withheld_path(self) -> None:
        manifest = json.loads(
            (ROOT / "RELEASE_MANIFEST.json").read_text(encoding="utf-8"))
        released = {p for p, s in manifest["paths"].items()
                    if s in ("project_own", "metadata_only",
                             "attribution_required")}
        for prefix in ("jsonl", "derived", "splits", "benchmark", "training",
                       "datasets", "experiments", "Vbeta"):
            covered = {p for p in manifest["paths"]
                       if p.split("/")[0].startswith(prefix)}
            self.assertTrue(covered, prefix)
            self.assertFalse(covered & released,
                             f"{prefix} must not be inside the released set")
        licence = (ROOT / "LICENSE").read_text(encoding="utf-8")
        low = " ".join(licence.lower().split())
        self.assertIn("not licensed here", low)
        self.assertIn("does not cover", low)

    def test_the_open_questions_are_published(self) -> None:
        manifest = json.loads(
            (ROOT / "RELEASE_MANIFEST.json").read_text(encoding="utf-8"))
        notice = (ROOT / "NOTICE.md").read_text(encoding="utf-8")
        questions = manifest["open_questions"]
        self.assertGreaterEqual(len(questions), 5)
        for q in questions:
            self.assertTrue(q["human_review_required"], q["id"])
            self.assertTrue(q["why_not_mechanically_resolvable"], q["id"])
            self.assertIn(q["id"], notice, q["id"])



class RightsGateLiveTree(unittest.TestCase):
    """Read-only checks against the real repository."""

    def test_gate_is_runnable_and_reports_the_known_findings(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(GATE), "--quiet", "--json"],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", cwd=str(ROOT))
        payload = json.loads(proc.stdout)
        self.assertEqual(proc.returncode, 0, json.dumps(payload)[:1200])
        found = {r["code"] for r in payload["reasons"]}
        # the V4 statuses were reconciled into V4/licensing.json; a contradiction
        # is now a failure, not a standing finding, and the gate must say so
        self.assertNotIn("LICENCE_STATUS_CONTRADICTION", found)
        self.assertNotIn("UNKNOWN_MASKS_DECLARED_LICENCE", found)
        self.assertNotIn("POLICY_FRAMING_MISSING", found)
        # what is still true is reported as a limitation, not silently dropped
        limits = {item["code"] for item in payload.get("noted_limitations", [])}
        self.assertIn("UPSTREAM_HASH_NOT_RECORDED", limits)

    def test_distribution_view_carries_no_copied_expression(self) -> None:
        view = ROOT / "distribution_v1"
        if not view.is_dir():
            self.skipTest("distribution_v1 not built")
        proc = subprocess.run(
            [sys.executable, str(GATE), "--quiet", "--json"],
            capture_output=True, text=True, encoding="utf-8",
            errors="replace", cwd=str(ROOT))
        reasons = json.loads(proc.stdout)["reasons"]
        copied = [r for r in reasons if r["code"] in (
            "DIST_FORBIDDEN_CODE_PRESENT", "DIST_COPIED_PROSE_OVER_QUOTA",
            "DIST_PERSONAL_DATA_PRESENT", "DIGEST_VERBATIM_OVERLAP",
            "HASH_MISMATCH", "MANIFEST_HASH_MISMATCH")]
        self.assertEqual(copied, [], f"the view must be clean: {copied}")

    def test_inventory_counts_are_recomputed_not_typed(self) -> None:
        """The committed inventory must be internally consistent, not
        self-referential.

        The old form of this test compared the stored `scan.tracked_files`
        with `len(git ls-files)` in THIS checkout. That value describes the
        generating machine's git index; a fresh clone legitimately differs,
        so the assertion could only pass on the exact staging state that
        generated the artefact (it failed on all four CI matrix jobs). The
        portable rule, shared with scripts/check_rights_consistency.py: a
        check may only compare quantities that any checkout computes
        identically. So: the inventory's stated tracked-file count equals
        the number of file rows it itself enumerates, its byte total equals
        the sum of its rows, its per-layer counts are internally consistent,
        and every repo-relative path it cites exists in this checkout.
        """
        inv_path = ROOT / "reports" / "rights_inventory.json"
        if not inv_path.is_file():
            self.skipTest("inventory not generated")
        inv = json.loads(inv_path.read_text(encoding="utf-8"))
        per_layer = sum(sum(c.values())
                        for c in inv["totals_by_layer"].values())
        total = sum(inv["totals_by_class"]["expressive_items"].values())
        self.assertEqual(per_layer, total)
        self.assertEqual(inv["scan"]["tracked_files"], len(inv["files"]))
        self.assertEqual(inv["scan"]["tracked_bytes"],
                         sum(r["bytes"] for r in inv["files"]))
        self.assertEqual(inv["scan"]["record_layers_scanned"],
                         len(inv["scan"]["record_layers_list"]))
        self.assertEqual(inv["scan"]["text_artefacts_scanned"],
                         len(inv["text_artefact_scan"]))
        missing = [r["path"] for r in inv["files"]
                   if not (ROOT / r["path"]).is_file()]
        self.assertEqual(missing, [],
                         "every path the inventory cites must exist in any "
                         "checkout of the commit that carries it")
        # the audit must not be limited to the 424 self-flagged v1 rows
        self.assertGreater(len(inv["totals_by_layer"]), 40)

    def test_committed_artefacts_carry_no_machine_local_paths(self) -> None:
        """Regression guard: the committed rights artefacts must stay
        environment-independent.

        A machine-local absolute path (Windows drive-letter, `/home/`,
        `/Users/`) baked into reports/rights_inventory.json ties the gate to
        the one checkout that generated it, which is the flaw that made
        rights-consistency permanently red on GitHub Actions. The scan uses a
        boundary before the drive letter so `https://` URLs — which are
        legitimate repo-relative content pointers — are not false positives.
        """
        drive_local = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]:[\\/]")
        artefacts = [ROOT / "reports" / "rights_inventory.json",
                     ROOT / "reports" / "rights_history_exposure.json",
                     ROOT / "distribution_v1" / "MANIFEST.json"]
        for p in artefacts:
            if not p.is_file():
                self.skipTest(f"{p.name} not generated")
            text = p.read_text(encoding="utf-8", errors="replace")
            for lineno, line in enumerate(text.splitlines(), 1):
                for needle in ("/home/", "/Users/"):
                    self.assertNotIn(
                        needle, line,
                        f"{p.name}:{lineno} embeds a machine-local path "
                        f"({needle!r}); the artefact must be environment-"
                        f"independent")
                self.assertIsNone(
                    drive_local.search(line),
                    f"{p.name}:{lineno} embeds a drive-letter absolute path; "
                    f"catalogue paths must stay repo-relative")


if __name__ == "__main__":
    unittest.main()
