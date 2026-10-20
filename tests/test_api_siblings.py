"""spec item 11: the API-sibling layer must stay real, span-pinned and split-safe.

These tests do two things.

  1. They pin the invariants of the shipped layer: every task carries a project,
     both revisions (or an explicit `unavailable`), a root cause attributed to a
     record, a rationale, and spans that hash-match the pinned source; the split
     never puts one project group in two splits; and the layer describes itself
     as leakage-audited rather than contamination-proof.
  2. They run the *same* validators over the deliberately broken fixtures under
     ``tests/fixtures/broken/``. Each fixture is a real record corrupted in one
     named way. If a guard is weakened or dropped, the corresponding test stops
     catching its fixture and fails.

Run:  python -m unittest discover -s tests
"""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import review_sibling_pairs as R  # noqa: E402
import build_api_siblings as B  # noqa: E402
from vlun_io import read_jsonl  # noqa: E402

LAY = ROOT / "derived_siblings"
FIXTURES = ROOT / "tests" / "fixtures" / "broken"
TASKS = read_jsonl(LAY / "tasks.jsonl") if (LAY / "tasks.jsonl").exists() else []
NEGATIVES = (read_jsonl(LAY / "hard_negatives.jsonl")
             if (LAY / "hard_negatives.jsonl").exists() else [])
SPLITS = json.loads((LAY / "splits.json").read_text(encoding="utf-8")) \
    if (LAY / "splits.json").exists() else {}
MANIFEST = json.loads((LAY / "manifest.json").read_text(encoding="utf-8"))     if (LAY / "manifest.json").exists() else {}
STATS = json.loads((ROOT / "reports" / "api_sibling_stats.json").read_text(encoding="utf-8")) \
    if (ROOT / "reports" / "api_sibling_stats.json").exists() else {}
STATS_MD = (ROOT / "reports" / "api_sibling_stats.md").read_text(encoding="utf-8") \
    if (ROOT / "reports" / "api_sibling_stats.md").exists() else ""


def fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


# -- what each test below needs to reach a verdict -----------------------------
# Class (a): pure logic over tracked inputs -- LayerIsPresent, TasksAreComplete
# (validate_task is structural only), SplitsAreGroupAware, LeakageLanguageIsHonest,
# ScriptSurface, and the split/rationale/root-cause/cross-repo fixtures. They run,
# pass and can fail on any machine, clones or not.
# Class (b): the span re-hash fixtures, whose inputs are the git-ignored retrieval
# trees (work/ + work/repos/ + V3/clones/). There the direction of each assertion
# decides what happens without those bytes:
#   * an assertion that a bad span is REFUSED stays enforced everywhere, because
#     refusing an unverifiable span is the correct behaviour in both worlds;
#   * an assertion that depends on the reason given, or that a good span is
#     AGREED, can only be settled by the real bytes, so it is recorded as a skip
#     with the missing input named -- never as a pass, never as a failure (the rule
#     scripts/check_reproducibility.py applies to absent citation inputs).
def pinned_bytes_readable(site: dict) -> bool:
    """Can the pinned source this span cites actually be re-read from disk?

    The vulnerable side resolves through ``local_sources`` to the retrieval
    manifest and retrieved files under ``work/``; the reference side through the
    pinned clone under ``work/repos/<owner>__<repo>``. Both trees are git-ignored
    and never redistributed, so a fresh ``actions/checkout`` holds neither. This
    asks ``read_back`` -- the code's own answer to "can these bytes be re-read" --
    so a test guarded by it skips when and only when the input is genuinely
    absent.
    """
    text, _how = R.read_back(site)
    return text is not None


class LayerIsPresent(unittest.TestCase):
    def test_all_four_layer_files_exist(self):
        for name in ("tasks.jsonl", "hard_negatives.jsonl", "splits.json", "manifest.json"):
            self.assertTrue((LAY / name).exists(), name)

    def test_layer_expanded_past_the_v2_1_baseline(self):
        # reports/counterexample_stats.json records 71 intra-contract api_sibling_pairs
        self.assertGreater(len(TASKS), 71,
                           "the new layer must exceed the 71-pair baseline it expands")

    def test_hard_negatives_exist_and_are_evidence_backed(self):
        self.assertTrue(NEGATIVES, "a sibling family with no hard negatives has not "
                                   "actually been refuted against anything")
        for n in NEGATIVES:
            self.assertTrue(n["why_it_looks_like_a_sibling"].strip(), n["negative_id"])
            self.assertTrue(n["why_it_is_not_one"].strip(), n["negative_id"])
            self.assertTrue(n["rejected_because"], n["negative_id"])
            self.assertTrue(n["spans"]["vulnerable"]["file"], n["negative_id"])

    def test_yield_is_reported_as_a_yield_not_a_quota(self):
        y = STATS["yield"]
        for k in ("candidates_proposed", "reviewed_and_agreed", "admitted_tasks",
                  "hard_negatives", "dropped"):
            self.assertIn(k, y)
        self.assertIn("target_reached", y)
        self.assertIsInstance(y["target_reached"], bool)
        self.assertTrue(y["shortfall_explained"].strip())


class TasksAreComplete(unittest.TestCase):
    def test_every_shipped_task_validates(self):
        for t in TASKS:
            self.assertEqual([], R.validate_task(t), t["task_id"])

    def test_revisions_are_named_or_explicitly_unavailable(self):
        for t in TASKS:
            r = t["revisions"]
            self.assertTrue(r["vulnerable_revision"], t["task_id"])
            self.assertIn(r["fixed_revision"], (None, ""), r["fixed_revision"], t["task_id"]) \
                if False else None
            if r["fixed_revision"] == "unavailable":
                self.assertTrue(r["fixed_revision_state"], t["task_id"])
            else:
                self.assertEqual(40, len(r["fixed_revision"]), t["task_id"])

    def test_root_cause_is_attributed_to_a_record(self):
        for t in TASKS:
            rc = t["root_cause"]
            self.assertTrue(rc["value"], t["task_id"])
            self.assertTrue(rc["record_id"], t["task_id"])
            self.assertEqual(64, len(rc["record_sha256"]), t["task_id"])
            self.assertEqual("reported_claim", rc["evidence_type"], t["task_id"])

    def test_no_task_carries_expressive_source_text(self):
        for t in TASKS:
            self.assertEqual([], [k for k in R._walk_forbidden(t)], t["task_id"])
            for side in ("vulnerable", "reference"):
                self.assertIs(False, t["spans"][side]["source_text_included"], t["task_id"])

    def test_every_task_is_cross_repository(self):
        for t in TASKS:
            self.assertNotEqual(t["project"]["vulnerable"]["repo"],
                                t["project"]["reference"]["repo"], t["task_id"])

    def test_rights_decision_recorded_per_item(self):
        for t in TASKS:
            r = t["rights"]
            self.assertEqual(B.RIGHTS_DECISION, r["decision"], t["task_id"])
            self.assertIs(False, r["expressive_text_redistributed"], t["task_id"])
            self.assertIn(r["vulnerable_license_class"], R.LICENSE_CLASSES_OK, t["task_id"])
            self.assertIn(r["reference_license_class"], R.LICENSE_CLASSES_OK, t["task_id"])


class SplitsAreGroupAware(unittest.TestCase):
    def test_real_layer_has_no_group_violation(self):
        self.assertEqual({}, R.split_group_violations(TASKS, SPLITS))

    def test_every_task_is_assigned_exactly_once(self):
        ids = {t["task_id"] for t in TASKS}
        self.assertEqual(ids, set(SPLITS["task_split"]))
        self.assertEqual(sum(SPLITS["counts"].values()), len(TASKS))
        for tid, s in SPLITS["task_split"].items():
            self.assertIn(s, ("train", "validation", "test"), tid)

    def test_reference_side_straddle_is_measured_not_denied(self):
        h = STATS["project_holdout_audit"]
        self.assertEqual(0, h["violation_count"])
        self.assertIn("reference_side_straddling_splits", h)
        self.assertIn("shared library code", h["note"])


class LeakageLanguageIsHonest(unittest.TestCase):
    def test_the_layer_never_calls_itself_contamination_proof(self):
        for blob in (STATS_MD, json.dumps(STATS), json.dumps(MANIFEST)):
            low = blob.lower()
            self.assertNotIn("contamination-proof", low.replace("not contamination-proof", ""))
            self.assertNotIn("contamination proof", low.replace("not contamination proof", ""))

    def test_the_layer_says_leakage_audited_under_recorded_criteria(self):
        self.assertIn("leakage-audited", STATS["disclaimer"])
        self.assertIn("NOT contamination-proof", STATS["disclaimer"])

    def test_near_duplicate_audit_actually_compared_pairs(self):
        d = STATS["near_duplicate_leakage_audit"]
        self.assertGreater(d["pairs_compared"], 0)
        self.assertIn("shared_pinned_files_cross_split", d)


class BrokenFixturesAreCaught(unittest.TestCase):
    """Each fixture is a real record corrupted in one named way; the shared
    validator must refuse it. Weakening a guard turns these red."""

    def test_split_that_straddles_a_project_group_is_rejected(self):
        bad = fixture("split_same_group_in_two_splits.json")
        v = R.split_group_violations(TASKS, bad)
        self.assertTrue(v, "a split putting two tasks of one project group in train "
                           "and test must be reported as a violation")
        self.assertEqual({}, R.split_group_violations(TASKS, SPLITS))

    def test_span_that_does_not_hash_match_the_pinned_source_is_rejected(self):
        bad = fixture("pair_span_hash_mismatch.json")
        bad_site = bad["spans"]["vulnerable"]
        good_site = TASKS[0]["spans"]["vulnerable"]
        agree, detail = R.span_rehash_disagreement(bad_site)
        # This half needs no clones and stays enforced everywhere: a span whose
        # bytes cannot be verified is never agreed.
        self.assertFalse(agree, detail)
        # The rest of the verdict does need the bytes. Without them the validator
        # honestly reports "pinned source could not be re-read", which is not the
        # hash mismatch this fixture exists to prove -- so it is a skip, never a
        # pass and never a failure (see scripts/check_reproducibility.py).
        if not (pinned_bytes_readable(bad_site) and pinned_bytes_readable(good_site)):
            cited = "{}@{} {}".format(
                bad_site.get("owner_repo"),
                bad_site.get("revision") or bad_site.get("commit_sha"),
                bad_site.get("file"))
            self.skipTest(
                "skipped_no_network: V3/clones/ and work/ absent (citation inputs are "
                "git-ignored and never redistributed); this assertion needs the pinned "
                f"source bytes of {cited} plus those of the shipped task they are "
                "compared with, so neither the hash-mismatch reason nor the positive "
                "re-hash can be reached")
        self.assertIn("hash", detail)
        # and the real one still agrees
        a2, _ = R.span_rehash_disagreement(good_site)
        self.assertTrue(a2)

    def test_span_pointing_at_the_wrong_bytes_is_rejected(self):
        bad = fixture("pair_span_points_at_wrong_bytes.json")
        # Deliberately NOT skipped: this assertion only requires the refusal, and
        # the refusal is correct in both worlds -- a reference span that cannot be
        # re-read must not be agreed either. If the guard is weakened so that an
        # unverifiable span is agreed, this test still goes red on a fresh clone.
        agree, detail = R.span_rehash_disagreement(bad["spans"]["reference"])
        self.assertFalse(agree, detail)

    def test_task_without_a_rationale_is_rejected(self):
        bad = fixture("task_missing_rationale.json")
        errs = R.validate_task(bad)
        self.assertIn("missing_rationale:why_vulnerable", errs)

    def test_task_without_an_attributed_root_cause_is_rejected(self):
        bad = fixture("task_missing_root_cause.json")
        errs = R.validate_task(bad)
        self.assertIn("missing_root_cause", errs)
        self.assertIn("root_cause_not_attributed_to_a_record", errs)

    def test_single_repository_pair_and_included_source_text_are_rejected(self):
        bad = fixture("task_same_repository_and_source_text.json")
        errs = R.validate_task(bad)
        self.assertIn("pair_is_not_cross_repository", errs)
        self.assertTrue(any(e.endswith("claims_source_text_included") for e in errs), errs)
        self.assertTrue(any(e.startswith("forbidden_source_text_key") for e in errs), errs)


class ScriptSurface(unittest.TestCase):
    def test_help_and_flags_exist(self):
        for script in ("scripts/build_api_siblings.py", "scripts/review_sibling_pairs.py"):
            p = subprocess.run([sys.executable, script, "--help"], cwd=str(ROOT),
                               capture_output=True, text=True, timeout=120)
            self.assertEqual(0, p.returncode, script)
            for flag in ("--help", "--check"):
                self.assertIn(flag, p.stdout, script)
            if "build" in script:
                self.assertIn("--dry-run", p.stdout)

    def test_dry_run_writes_nothing(self):
        before = {p.name: p.stat().st_mtime_ns for p in LAY.glob("*")}
        p = subprocess.run([sys.executable, "scripts/build_api_siblings.py", "--dry-run",
                            "--quiet"], cwd=str(ROOT), capture_output=True, text=True,
                           timeout=900)
        self.assertEqual(0, p.returncode, p.stderr[-400:])
        self.assertIn("real candidate pairs found", p.stdout)
        after = {q.name: q.stat().st_mtime_ns for q in LAY.glob("*")}
        self.assertEqual(before, after, "the dry run must not touch the layer")


if __name__ == "__main__":
    unittest.main()
