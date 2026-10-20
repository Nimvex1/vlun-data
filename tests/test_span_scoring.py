"""Evidence-span scoring guards (spec item 10).

These tests are engineered so that they FAIL against a broken pipeline. They
consume deliberately-broken fixtures under tests/fixtures/broken/ and assert
that the real code rejects or correctly classifies each broken case:

  * a model-facing prompt that leaks the expected span/label is REJECTED by the
    build-time leak guard (build_span_tasks._leak_check raises);
  * a span flagged `verified` whose bytes do not hash-match the pinned source
    is NOT credited as supporting (scored against the source, not the label);
  * abstention is reported on its OWN axis and is never folded into
    answer-correctness.

A positive test also scans the generated model-facing tasks.jsonl against the
held-out answer key to prove nothing leaked into the prompts.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import build_span_tasks as B  # noqa: E402
import score_span_tasks as S  # noqa: E402

BROKEN = ROOT / "tests" / "fixtures" / "broken"
ANSWER_KEY = ROOT / "derived_span_tasks" / "answer_key.jsonl"
TASKS = ROOT / "derived_span_tasks" / "tasks.jsonl"


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _answer_key_by_id() -> dict:
    out = {}
    with open(ANSWER_KEY, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                r = json.loads(line)
                out[r["task_id"]] = r
    return out


def pinned_bytes_readable(key: dict) -> bool:
    """Can the pinned source behind this key's expected span be re-read?

    `source_location` points into ``V3/clones/``, which is git-ignored and never
    redistributed, so a fresh CI checkout has none of those bytes. Asking
    ``score_span_tasks.pinned_span_hash`` -- the very helper the scorer under test
    uses -- means a guarded assertion skips when and only when the input is
    genuinely absent, and still runs (and still fails) wherever the clones are.
    """
    sp = key.get("expected_span") or {}
    start, end = sp.get("start_byte"), sp.get("end_byte")
    if not (isinstance(start, int) and isinstance(end, int) and 0 <= start < end):
        return False
    return S.pinned_span_hash(sp.get("source_location"), start, end) is not None


class LeakGuardTests(unittest.TestCase):
    def test_leaking_prompt_is_rejected(self):
        """A prompt carrying the expected label + span bounds must raise."""
        fx = _load(BROKEN / "leaking_prompt_task.json")
        real = _answer_key_by_id()[fx["task_id"]]
        with self.assertRaises(AssertionError):
            B._leak_check(fx["prompt"], real["expected_answer"],
                          real["expected_span"])

    def test_clean_generated_prompt_passes(self):
        """The real generated prompt for that task must NOT raise."""
        real = _answer_key_by_id()
        # every generated prompt must survive its own key's leak check
        with open(TASKS, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                t = json.loads(line)
                k = real[t["task_id"]]
                ans = k["expected_answer"] if k["answerable"] else None
                B._leak_check(t["prompt"], ans, k["expected_span"])

    def test_no_heldout_content_in_model_facing_file(self):
        """tasks.jsonl must not embed span byte offsets or hashes."""
        real = _answer_key_by_id()
        blob = TASKS.read_text(encoding="utf-8")
        for k in real.values():
            sp = k["expected_span"]
            h = sp.get("span_sha256")
            if isinstance(h, str) and len(h) >= 32:
                self.assertNotIn(h[:32], blob,
                                 "expected span hash leaked into tasks.jsonl")


class SupportVerificationTests(unittest.TestCase):
    def test_verified_label_with_nonmatching_bytes_is_not_supported(self):
        """The crux: support is checked against the pinned bytes, not the flag.

        Not skipped anywhere. The expected (tampered) hash is recorded in the key,
        so "a span that does not hash-match is NOT credited" is enforced on any
        machine: with the pinned bytes present the hash genuinely mismatches, and
        with them absent the scorer has nothing to credit and still returns False.
        """
        bad_key = _load(BROKEN / "bad_hash_verified_key.json")
        sub = _load(BROKEN / "exact_bounds_bad_hash_submission.json")
        res = S.score_one(sub, bad_key, tolerance=0)
        # span_availability claims verified and bounds are exact, but the bytes
        # do not hash to the tampered span_sha256 -> support must be False.
        self.assertEqual(bad_key["span_availability"], "verified")
        self.assertFalse(res["axis_span_support"]["supported"],
                         "a span whose bytes do not match the source must not "
                         "be credited as supporting")

    def test_correct_hash_matches_and_is_supported(self):
        """Same task with the true hash -> support True (positive control)."""
        real = _answer_key_by_id()
        bad_key = _load(BROKEN / "bad_hash_verified_key.json")
        good = real[bad_key["task_id"]]
        sub = _load(BROKEN / "exact_bounds_bad_hash_submission.json")
        # Crediting a correct hash is only a verdict if the cited bytes can be
        # re-read; the positive control is what gives the negative test above its
        # teeth. Without V3/clones/ the scorer honestly reports "nothing to match",
        # so this is recorded as a skip -- never as a pass, never as a failure
        # (the rule scripts/check_reproducibility.py applies to absent inputs).
        if not pinned_bytes_readable(good):
            sp = good["expected_span"]
            self.skipTest(
                "skipped_no_network: V3/clones/ absent; this assertion needs the "
                "pinned source bytes at "
                f"{sp.get('source_location')}@{sp.get('clone_head')} "
                f"[{sp.get('start_byte')}:{sp.get('end_byte')}] to be re-read, and a "
                "fresh checkout never has them")
        res = S.score_one(sub, good, tolerance=0)
        self.assertTrue(res["axis_span_support"]["supported"])
        self.assertTrue(res["axis_citation_exactness"]["exact"])


class AbstentionSeparationTests(unittest.TestCase):
    def test_abstention_is_its_own_axis_not_answer_correctness(self):
        """Abstaining on a verifiable task => wrong_abstain, and the answer axis
        records it as NOT attempted (so it is never folded into answer error)."""
        fx = _load(BROKEN / "abstain_on_verified_task.json")
        key = _answer_key_by_id()[fx["task_id"]]
        res = S.score_one(fx["submission"], key, tolerance=0)
        self.assertEqual(key["span_availability"], "verified")
        self.assertEqual(res["axis_abstention"], "wrong_abstain")
        # answer-correctness axis must NOT have counted this as an attempt
        self.assertFalse(res["axis_answer"]["attempted"])

    def test_metrics_expose_abstention_separately(self):
        """_aggregate returns distinct answer_correctness and abstention blocks."""
        keys = list(_answer_key_by_id().values())[:80]
        subs = [{"task_id": k["task_id"], "abstain": True} for k in keys]
        agg = S.run(subs, {k["task_id"]: k for k in keys}, 0)["metrics"]
        self.assertIn("abstention", agg)
        self.assertIn("answer_correctness", agg)
        self.assertNotEqual(agg["abstention"], agg["answer_correctness"])
        # no abstention value may live inside the answer-correctness numbers
        self.assertEqual(agg["answer_correctness"]["attempted"], 0)


if __name__ == "__main__":
    unittest.main()
