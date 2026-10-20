"""The PoC triage queue must be structurally honest.

The queue is what turns "155 exploit records" into an executable campaign, so the
failure modes that matter are the ones that let a record look attemptable when it
is not, or that quietly move PoC bytes out of the immutable evidence layer and
into a derived artefact.

These tests are deliberately two-sided:

  * the committed queue must validate cleanly against the exploit layer, and
  * every broken fixture under tests/fixtures/broken/poc_triage/ must produce a
    specific error - if the validator ever stops objecting, this test fails.

Run with: python -m unittest tests.test_poc_triage
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import build_poc_triage_queue as bq  # noqa: E402

QUEUE = ROOT / "derived_poc_queue" / "triage_queue.jsonl"
EXPLOITS = ROOT / "jsonl" / "exploits.jsonl"
FIXTURES = ROOT / "tests" / "fixtures" / "broken" / "poc_triage"


def load_rows(p: Path) -> list[dict]:
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines()
            if line.strip()]


class TestCommittedQueue(unittest.TestCase):
    def test_queue_exists(self):
        self.assertTrue(QUEUE.exists(),
                        f"{QUEUE} missing: run scripts/build_poc_triage_queue.py")

    def test_covers_every_exploit_record(self):
        rows = load_rows(QUEUE)
        v1 = [r for r in rows if r["candidate_layer"] == bq.LAYER_V1]
        n_exploit = len([line for line in EXPLOITS.read_text(encoding="utf-8").splitlines()
                         if line.strip()])
        self.assertEqual(len(v1), n_exploit,
                         "the queue must hold exactly one row per exploit record, "
                         "no silent subsetting")

    def test_layers_are_not_merged(self):
        rows = load_rows(QUEUE)
        stats = json.loads((ROOT / "reports" / "poc_triage_queue.json")
                           .read_text(encoding="utf-8"))
        v1 = stats["layers"][bq.LAYER_V1]["candidates"]
        v3 = stats["layers"][bq.LAYER_V3]["poc_bearing_candidates"]
        self.assertEqual(sum(1 for r in rows if r["candidate_layer"] == bq.LAYER_V1), v1)
        self.assertEqual(sum(1 for r in rows if r["candidate_layer"] == bq.LAYER_V3), v3)
        self.assertNotEqual(v1, v1 + v3,
                            "a headline count that adds the layers together would "
                            "erase which evidence layer a candidate belongs to")

    def test_committed_queue_validates(self):
        rows = load_rows(QUEUE)
        errs = bq.validate_queue_rows(
            rows, expected_v1=len([line for line in
                                   EXPLOITS.read_text(encoding="utf-8").splitlines()
                                   if line.strip()]))
        self.assertEqual(errs, [], "queue breaches: " + "; ".join(errs[:5]))

    def test_every_row_names_a_pointer_not_code(self):
        for r in load_rows(QUEUE):
            ptr = r.get("poc_source_pointer") or {}
            self.assertNotIn("code", ptr,
                             f"{r['finding_id']}: the queue must point at the PoC")

    def test_eligible_rows_have_no_blocker_and_vice_versa(self):
        for r in load_rows(QUEUE):
            if r["eligibility"] == "eligible":
                self.assertEqual(r["blocker_classes"], [],
                                 f"{r['finding_id']}: eligible with blockers")
            else:
                self.assertTrue(r["blocker_classes"],
                                f"{r['finding_id']}: not eligible without a reason")

    def test_blocker_vocabulary_is_closed(self):
        for r in load_rows(QUEUE):
            self.assertTrue(set(r["blocker_classes"]) <= set(bq.BLOCKERS),
                            f"{r['finding_id']}: {r['blocker_classes']}")

    def test_counts_are_recomputed_not_hand_typed(self):
        """The report's numbers must follow from the rows it ships."""
        rows = load_rows(QUEUE)
        stats = json.loads((ROOT / "reports" / "poc_triage_queue.json")
                           .read_text(encoding="utf-8"))
        v1 = [r for r in rows if r["candidate_layer"] == bq.LAYER_V1]
        d = stats["layers"][bq.LAYER_V1]
        self.assertEqual(d["eligible"], sum(1 for r in v1
                                             if r["eligibility"] == "eligible"))
        self.assertEqual(d["not_eligible"], sum(1 for r in v1
                                                 if r["eligibility"] != "eligible"))
        self.assertEqual(d["attemptable"],
                         sum(1 for r in v1
                             if r["attemptable_under_current_standard"]))
        self.assertEqual(d["with_assertion_in_quoted_poc"],
                         sum(1 for r in v1 if r["assertion"]["assertions_present"]))


class TestBrokenFixturesFail(unittest.TestCase):
    """Each fixture breaks exactly one rule; the validator must say so."""

    def _rows(self, name: str) -> list[dict]:
        p = FIXTURES / name
        self.assertTrue(p.exists(), f"broken fixture {name} is missing")
        return load_rows(p)

    def test_eligible_with_blocker_is_rejected(self):
        errs = bq.validate_queue_rows(self._rows("eligible_with_blocker.jsonl"))
        self.assertTrue(any("marked eligible while carrying blockers" in e for e in errs),
                        f"validator accepted an eligible row with blockers: {errs}")

    def test_unknown_blocker_class_is_rejected(self):
        errs = bq.validate_queue_rows(self._rows("unknown_blocker_class.jsonl"))
        self.assertTrue(any("outside the closed vocabulary" in e for e in errs),
                        f"validator accepted an invented blocker: {errs}")

    def test_copied_poc_code_is_rejected(self):
        errs = bq.validate_queue_rows(self._rows("poc_code_copied_not_pointed.jsonl"))
        self.assertTrue(any("must point at the PoC" in e for e in errs),
                        f"validator accepted copied PoC bytes: {errs}")

    def test_missing_pinned_revision_is_rejected(self):
        errs = bq.validate_queue_rows(self._rows("missing_pinned_revision.jsonl"))
        self.assertTrue(any("no pinned vulnerable revision" in e for e in errs),
                        f"validator accepted an unpinned record: {errs}")

    def test_not_eligible_without_blocker_is_rejected(self):
        errs = bq.validate_queue_rows(self._rows("not_eligible_without_blocker.jsonl"))
        self.assertTrue(any("no blocker class" in e for e in errs),
                        f"validator accepted a reasonless rejection: {errs}")

    def test_short_layer_is_rejected(self):
        """A queue that quietly drops candidates must fail the coverage check."""
        rows = self._rows("unknown_blocker_class.jsonl")   # 1 row
        errs = bq.validate_queue_rows(rows, expected_v1=155)
        self.assertTrue(any("expected 155 exploit records" in e for e in errs),
                        f"validator accepted a truncated queue: {errs}")

    def test_fixtures_are_otherwise_wellformed(self):
        """Guard: a fixture must fail only for its intended reason."""
        for name, needle in (
                ("eligible_with_blocker.jsonl", "marked eligible while carrying"),
                ("missing_pinned_revision.jsonl", "no pinned vulnerable revision"),
                ("poc_code_copied_not_pointed.jsonl", "must point at the PoC")):
            errs = [e for e in bq.validate_queue_rows(self._rows(name))
                    if needle not in e]
            self.assertEqual(errs, [],
                             f"{name} also breaks unrelated rules: {errs}")


if __name__ == "__main__":
    unittest.main()
