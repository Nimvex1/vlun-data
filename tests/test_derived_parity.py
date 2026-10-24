#!/usr/bin/env python3
"""The derived layer is reproducible from the builders that produced it.

`derived/records.jsonl` is the published artefact of record. The rebuild
gate (scripts/check_reproducibility.py, the `derived/ rebuild parity`
check) replays

    build_derived.py -> resolve_citations.py -> build_derived.py
    --migrate-record-hashes

and requires the bytes to come back identical. Three places used to make
that impossible, and this module pins all three:

  A. the taxonomy block's SHAPE. The layer carries a block that no builder
     emitted: no top-level `rule`, no `c4_original` inside a label, and for
     the 43 records with no vulnerability class no `labels`/`multi_label`/
     `vocabulary` at all. scripts/taxonomy.py emitted a superset, so every
     one of the 722 records differed.
  B. `attacker_model.attacker_identity.source_refs`. The layer states the
     pointer on exactly the 147 records whose identity was derived by a
     rule and omits the key on the 575 whose identity was quoted from a
     source or left unknown. The builder emitted the key every time, empty
     when there was nothing to point at.
  C. where the immutable provenance pin lives. The layer carries it in the
     TOP-LEVEL provenance (`provenance.source_urls`, plus the
     `provenance.source_urls_unpinned` residual list), and keeps the
     original_evidence mirror verbatim. The builder wrote the pin into the
     mirror instead, which left the shipped layer citing a mutable branch
     and would have failed the `provenance_urls_immutable_or_declared` gate.

The tests read the layer and the source rows; they never rebuild the 722
records, so they stay fast.
Run:  python -m unittest discover -s tests
"""

from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import build_derived as bd  # noqa: E402
import taxonomy as tx  # noqa: E402
from check_reproducibility import residual_summary  # noqa: E402
from validate_checks import record_url_problems  # noqa: E402

DERIVED = ROOT / "derived" / "records.jsonl"
JSONL = ROOT / "jsonl"

_BLOB_SHA = re.compile(r"/blob/[0-9a-f]{40}/")


def _read_jsonl(path: Path) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _layer() -> list[dict]:
    return _read_jsonl(DERIVED)


def _source_rows() -> dict[str, dict]:
    """The v1 rows as committed, keyed by finding id."""
    out: dict[str, dict] = {}
    for family in ("findings.jsonl", "negative_findings.jsonl"):
        for row in _read_jsonl(JSONL / family):
            out[(row.get("finding") or {}).get("id")] = row
    return out


class TestTaxonomyShape(unittest.TestCase):
    """Group A: the taxonomy block is the block the layer publishes."""

    def test_classify_reproduces_every_committed_taxonomy_block(self):
        records = _layer()
        self.assertEqual(len(records), 722)
        for rec in records:
            finding = rec.get("finding") or {}
            self.assertEqual(
                tx.classify(finding), rec.get("taxonomy"),
                f"{rec.get('id')}: the builder's taxonomy block differs from "
                "the committed one")

    def test_the_block_carries_no_second_copy_of_the_rule_or_the_c4_string(self):
        for rec in _layer():
            block = rec.get("taxonomy") or {}
            self.assertNotIn("rule", block, rec.get("id"))
            for label in block.get("labels") or []:
                self.assertNotIn("c4_original", label, rec.get("id"))
                self.assertIn("rule", label, rec.get("id"))
                self.assertIn("source_refs", label, rec.get("id"))

    def test_a_record_without_a_class_states_only_the_absence(self):
        without = [r for r in _layer()
                   if not ((r.get("finding") or {}).get("vulnerability_classes")
                           or [])]
        self.assertEqual(len(without), 43)
        for rec in without:
            block = rec.get("taxonomy") or {}
            for key in ("labels", "multi_label", "vocabulary", "source_refs"):
                self.assertNotIn(key, block, rec.get("id"))
            self.assertEqual(block.get("category"), "Unknown")
            self.assertEqual(block.get("evidence_type"), "unknown")


class TestProvenancePlacement(unittest.TestCase):
    """Group C: the pin lives at the top level; the mirror stays verbatim."""

    def test_top_level_provenance_is_the_pinned_one(self):
        rows = _source_rows()
        for rec in _layer():
            row = rows[rec["id"]]
            self.assertEqual(
                bd.pin_provenance_urls(row.get("provenance"), row.get("source")),
                rec.get("provenance"),
                f"{rec['id']}: the top-level provenance is not the pinned one")

    def test_the_original_evidence_mirror_is_verbatim(self):
        rows = _source_rows()
        for rec in _layer():
            row = rows[rec["id"]]
            mirror = ((rec.get("original_evidence") or {})
                      .get("v1_schema") or {}).get("provenance")
            self.assertEqual(
                row.get("provenance") or {}, mirror,
                f"{rec['id']}: the original_evidence mirror is not the "
                "committed v1 provenance")

    def test_the_shipped_layer_has_no_mutable_undeclared_url(self):
        # The gate's own rule (scripts/validate_checks.py): a mutable branch
        # URL in the shipped layer must be declared in the record's residual
        # list. A rebuilt layer that kept the pin in the mirror would fail
        # this with 357 undeclared URLs in 172 records.
        bad = []
        for rec in _layer():
            problems = record_url_problems(rec)
            if problems:
                bad.append((rec["id"], problems[:2]))
        self.assertEqual(bad, [])


class TestAttackerIdentityPointer(unittest.TestCase):
    """Group B: a pointer is stated only where there is something to point at."""

    def test_the_layer_states_the_pointer_exactly_where_a_rule_fired(self):
        with_pointer = 0
        for rec in _layer():
            identity = (rec.get("attacker_model") or {}).get("attacker_identity") or {}
            basis = identity.get("basis")
            if basis == "derived_fact":
                with_pointer += 1
                self.assertEqual(identity.get("source_refs"),
                                 ["rule:build_derived.py:attacker_model"], rec.get("id"))
            else:
                self.assertNotIn("source_refs", identity, rec.get("id"))
        self.assertEqual(with_pointer, 147)

    def test_the_builder_omits_an_empty_pointer(self):
        row = {"source": {"repository": "repo"}, "security_reasoning": {}}

        # A rule fired: every cited entry point carries an access-control
        # modifier, so the identity is derived, not quoted.
        privileged = bd.attacker_model(
            row,
            [{"file": "repo/Contract.sol",
              "functions": [{"required_roles": ["owner"],
                             "modifiers": ["onlyOwner"]}]}],
            {"title": "the owner can drain the vault", "summary": "",
             "root_cause": ""})
        identity = privileged["attacker_identity"]
        self.assertEqual(identity["basis"], "derived_fact")
        self.assertEqual(identity["source_refs"],
                         ["rule:build_derived.py:attacker_model"])

        # A source names the actor: the identity is quoted, so there is no
        # rule to point at.
        quoted = bd.attacker_model(
            row, [], {"title": "any user can call drain()", "summary": "",
                      "root_cause": ""})
        identity = quoted["attacker_identity"]
        self.assertEqual(identity["basis"], "reported_claim")
        self.assertNotIn("source_refs", identity)

        # Nothing settles it: no basis, no pointer.
        unknown = bd.attacker_model(
            row, [], {"title": "a review of the module", "summary": "",
                      "root_cause": ""})
        identity = unknown["attacker_identity"]
        self.assertEqual(identity["basis"], "unknown")
        self.assertNotIn("source_refs", identity)


class TestAMutatedBuildIsDetected(unittest.TestCase):
    """The gate must go red on the shapes this module pins."""

    def _jsonl_bytes(self, records: list[dict]) -> bytes:
        return "".join(
            json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n"
            for r in records).encode("utf-8")

    def test_a_taxonomy_drift_is_named(self):
        records = _layer()[:3]
        committed = self._jsonl_bytes(records)
        mutated = []
        for rec in records:
            rec = json.loads(json.dumps(rec))
            rec["taxonomy"]["rule"] = "a rule the layer does not carry"
            mutated.append(rec)
        summary = residual_summary(committed, self._jsonl_bytes(mutated))
        self.assertIn("3/3 records differ", summary)
        self.assertIn("taxonomy.rule", summary)

    def test_a_provenance_drift_is_named(self):
        records = [r for r in _layer()
                   if any("/blob/" in u and "/blob/main/" not in u
                          for u in (r.get("provenance") or {}).get("source_urls")
                          or [])][:3]
        self.assertTrue(records)
        committed = self._jsonl_bytes(records)
        mutated = []
        for rec in records:
            rec = json.loads(json.dumps(rec))
            # a mutable branch URL where the layer carries an immutable pin
            rec["provenance"]["source_urls"] = [
                _BLOB_SHA.sub("/blob/main/", u)
                for u in rec["provenance"]["source_urls"]]
            mutated.append(rec)
        summary = residual_summary(committed, self._jsonl_bytes(mutated))
        self.assertIn("3/3 records differ", summary)
        self.assertIn("provenance.source_urls", summary)

    def test_an_empty_pointer_written_where_the_layer_has_none_is_named(self):
        records = [r for r in _layer()
                   if "source_refs" not in (r["attacker_model"]
                                           ["attacker_identity"])][:3]
        self.assertTrue(records)
        committed = self._jsonl_bytes(records)
        mutated = []
        for rec in records:
            rec = json.loads(json.dumps(rec))
            rec["attacker_model"]["attacker_identity"]["source_refs"] = []
            mutated.append(rec)
        summary = residual_summary(committed, self._jsonl_bytes(mutated))
        self.assertIn("3/3 records differ", summary)
        self.assertIn("attacker_model.attacker_identity.source_refs", summary)


if __name__ == "__main__":
    unittest.main()
