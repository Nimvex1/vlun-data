#!/usr/bin/env python3
"""Tests for the evaluation-leakage gate and report.

Three defects are guarded here, and each one must make a test fail:

  a. a protected evaluation record (or its payload) reaching the
     model-visible training corpus;
  b. a model-facing task that carries its own answer while the evaluation
     set is described as hidden -- the answer key is committed in this
     repository, so the honest description is OPEN-KEY;
  c. the model-visible training corpus shipping a held-out (test or
     validation) partition of an evaluation family.

Each test has a synthetic fixture that MUST fail, so a detector that stops
detecting cannot pass by accident, and an assertion about the real corpus,
so a corpus that regresses fails the build.

    python -m unittest tests.test_eval_leakage
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(
        name, str(ROOT / "scripts" / f"{name}.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


leak = _load("build_eval_leakage_report")
gate = _load("check_eval_leakage")

TASKS = ROOT / "benchmark" / "independent" / "secondary_holdout_tasks.jsonl"
KEYS = ROOT / "benchmark" / "independent" / "secondary_holdout_keys.jsonl"
MANIFEST = (ROOT / "benchmark" / "independent"
            / "secondary_holdout_manifest.json")


def read_jsonl(path):
    return [json.loads(x) for x in
            path.read_text(encoding="utf-8").splitlines() if x.strip()]


class TestProtectedRecordsStayOutOfTheCorpus(unittest.TestCase):
    """(a) a protected evaluation ID or example in model-visible training data."""

    def test_synthetic_protected_id_in_a_corpus_row_is_detected(self):
        """A planted row that names a protected record must be caught."""
        protected = {"2024-08-wildcat/H-01"}
        rows = [{"canonical_id": "2024-08-wildcat/H-01",
                 "provenance": {"record_ref": "2024-08-wildcat/H-01"},
                 "split": "train"}]
        bad = gate.protected_id_violations(rows, protected)
        self.assertTrue(bad, "a corpus row naming a protected record was "
                             "not reported")

    def test_synthetic_protected_text_in_a_corpus_row_is_detected(self):
        """A planted row that copies a held-out payload must be caught."""
        fam = "A_vulnerability_detection.jsonl"
        rows = leak.load_benchmark()
        held = [r for r in rows if r["family"].endswith(fam)
                and r["split"] == "test"]
        self.assertTrue(held, "family A has no held-out rows to copy from")
        payload = leak._benchmark_text(held[0]["row"])
        with tempfile.TemporaryDirectory() as tmp:
            planted = pathlib.Path(tmp) / "planted.jsonl"
            planted.write_text(json.dumps({
                "canonical_id": "x:1", "code_ref": None,
                "example_id": "x:1:detection",
                "input_text": payload, "label": True, "layer": "v1",
                "provenance": {"record_ref": "x:1", "source_id": "s"},
                "split": "train", "supervision": "verified", "task": "detection",
                "verification_level": "unknown", "weight": 1.0},
                sort_keys=True) + "\n", encoding="utf-8")
            corpus = leak.Corpus(leak.corpus_paths(pathlib.Path(tmp)))
            text = leak.norm_text(payload)
            hits = corpus.text_hits(text, leak.shingles(text))
            self.assertTrue(hits, "the text detector did not match a corpus "
                                  "row that is byte-identical to a held-out "
                                  "task payload")

    def test_the_real_corpus_carries_no_protected_record(self):
        """The committed corpus must be clean, not merely well-measured."""
        protected = leak.protected_identifiers()
        self.assertGreater(len(protected), 1000,
                           "the protected set looks empty; the measurement "
                           "would prove nothing")
        for path in leak.corpus_paths():
            rows = read_jsonl(path)
            self.assertEqual(
                gate.protected_id_violations(rows, protected), [],
                f"{path} carries a record that a benchmark family holds out")

    def test_the_real_report_finds_no_overlap(self):
        rep = json.loads((ROOT / "reports" / "eval_leakage_report.json")
                         .read_text(encoding="utf-8"))
        h = rep["overlap"]["heldout"]
        self.assertEqual(h["rows_with_id_overlap"], 0)
        self.assertEqual(h["rows_with_text_overlap"], 0)
        self.assertEqual(h["rows_with_identical_code_snippet"], 0)
        self.assertEqual(h["rows_whose_answer_key_is_reproduced_in_training"],
                         0)
        self.assertEqual(rep["verdict"], "clean")

    def test_the_committed_report_is_current(self):
        r = subprocess.run(
            [sys.executable, "scripts/build_eval_leakage_report.py", "--check"],
            cwd=str(ROOT), capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_the_gate_fails_on_a_planted_leak(self):
        """End to end: a corpus carrying a held-out record id fails the gate."""
        rows = read_jsonl(ROOT / "benchmark" / "A_vulnerability_detection.jsonl")
        held = [r for r in rows if r["split"] == "test"]
        self.assertTrue(held)
        rid = (held[0].get("source") or {}).get("record_id")
        self.assertTrue(rid)
        with tempfile.TemporaryDirectory() as tmp:
            planted = pathlib.Path(tmp) / "planted.jsonl"
            planted.write_text(json.dumps({
                "canonical_id": rid, "code_ref": None,
                "example_id": f"v1:{rid}:detection",
                "input_text": "TITLE: planted", "label": True, "layer": "v1",
                "provenance": {"record_ref": rid, "source_id": "Code4rena"},
                "split": "train", "supervision": "verified", "task": "detection",
                "verification_level": "unknown", "weight": 1.0},
                sort_keys=True) + "\n", encoding="utf-8")
            r = subprocess.run(
                [sys.executable, "scripts/check_eval_leakage.py",
                 "--corpus", tmp], cwd=str(ROOT), capture_output=True, text=True)
            self.assertEqual(r.returncode, 1,
                             "the gate passed a corpus carrying a held-out "
                             f"record id: {r.stdout}{r.stderr}")


class TestTaskPayloadAndKeyStatus(unittest.TestCase):
    """(b) task inputs must not expose their gold; the key must say it is open."""

    def test_synthetic_task_row_carrying_gold_is_detected(self):
        for field in ("gold", "label", "answer_key", "original_id", "group"):
            row = {"holdout_task_id": "x", "family_file": "f", "holdout": "h",
                   "input": {}, field: "anything"}
            self.assertIn(field, gate.answer_fields_in_task_row(row),
                          f"a task row carrying {field!r} was not reported")

    def test_the_committed_task_file_carries_no_answer_field(self):
        rows = read_jsonl(TASKS)
        self.assertGreater(len(rows), 100)
        for row in rows:
            self.assertEqual(gate.answer_fields_in_task_row(row), [],
                             f"task {row.get('holdout_task_id')!r} exposes "
                             f"its answer")
            self.assertIn("input", row)
            self.assertIn("holdout_task_id", row)

    def test_the_task_id_reveals_nothing(self):
        """The task id must be a digest, not the record id."""
        keys = {r["holdout_task_id"]: r for r in read_jsonl(KEYS)}
        self.assertTrue(keys)
        for tid, key in list(keys.items())[:200]:
            self.assertTrue(tid.startswith("holdout-"), tid)
            self.assertNotIn(str(key.get("original_id") or ""), tid)
            self.assertNotIn(str(key.get("group") or ""), tid)
            gold = str(key.get("gold") or "")
            # A one-character gold is a digit that occurs in any digest by
            # chance; a longer gold must not.
            if len(gold) >= 3:
                self.assertNotIn(gold, tid)

    def test_the_key_file_is_labelled_open_key(self):
        for row in read_jsonl(KEYS):
            self.assertEqual(str(row.get("key_status", "")).lower(), "open_key")
            self.assertIn("gold", row)

    def test_the_manifest_describes_the_key_as_it_actually_is(self):
        # The key file is withheld from the repository (it is regenerable from
        # the committed sources, so the holdout stays open-key). The manifest
        # may not claim a committed key the repository does not carry, nor a
        # withheld key it does carry.
        man = json.loads(MANIFEST.read_text(encoding="utf-8"))
        ak = man["answer_key"]
        self.assertEqual(ak["key_status"], "OPEN_KEY")
        tracked = gate.key_file_is_tracked()
        if tracked is not None:
            self.assertIs(ak["committed_in_repository"], tracked)
            self.assertIs(ak["tracked_in_git"], tracked)
        self.assertEqual(gate.key_status_violations(read_jsonl(KEYS), man), [])

    def test_a_manifest_claiming_a_committed_untracked_key_is_rejected(self):
        man = json.loads(MANIFEST.read_text(encoding="utf-8"))
        man["answer_key"]["committed_in_repository"] = True
        man["answer_key"]["tracked_in_git"] = True
        bad = gate.key_status_violations(read_jsonl(KEYS), man)
        if gate.key_file_is_tracked() is False:
            self.assertTrue(bad, "a manifest claiming a committed key the "
                                 "repository does not carry was accepted")

    def test_a_manifest_claiming_a_hidden_key_is_rejected(self):
        """A claim of hiddenness for a committed key must fail the check."""
        man = json.loads(MANIFEST.read_text(encoding="utf-8"))
        man["answer_key"]["hidden"] = True
        bad = gate.key_status_violations(read_jsonl(KEYS), man)
        self.assertTrue(bad, "a manifest claiming a hidden answer key was "
                             "accepted")

    def test_a_key_row_without_the_open_key_label_is_rejected(self):
        rows = read_jsonl(KEYS)
        rows[0] = dict(rows[0])
        rows[0]["key_status"] = "hidden"
        man = json.loads(MANIFEST.read_text(encoding="utf-8"))
        bad = gate.key_status_violations(rows, man)
        self.assertTrue(bad, "a key row that does not declare OPEN-KEY was "
                             "accepted")

    def test_no_row_holds_both_the_input_and_the_gold(self):
        """No committed file may put an input and its gold in one row."""
        for path in sorted((ROOT / "benchmark" / "independent").rglob("*.jsonl")):
            for row in read_jsonl(path):
                has_input = "input" in row
                has_gold = "gold" in row
                self.assertFalse(
                    has_input and has_gold,
                    f"{path} has a row with both the input and the gold")


class TestHeldOutPartitionsAreNotTrainingData(unittest.TestCase):
    """(c) the model-visible corpus must ship no held-out partition."""

    def test_synthetic_test_partition_row_is_detected(self):
        for split in ("test", "validation"):
            bad = gate.held_out_partition_violations(
                [{"split": split, "canonical_id": "x"}])
            self.assertTrue(bad, f"a {split!r} partition row was not reported")

    def test_synthetic_train_partition_row_is_accepted(self):
        self.assertEqual(
            gate.held_out_partition_violations([{"split": "train"}]), [])
        self.assertEqual(gate.held_out_partition_violations([{}]), [])

    def test_the_real_corpus_ships_no_held_out_partition(self):
        for path in leak.corpus_paths():
            rows = read_jsonl(path)
            bad = gate.held_out_partition_violations(rows)
            self.assertEqual(bad, [],
                             f"{path} ships a held-out partition: {bad}")

    def test_the_canonical_manifest_lists_only_model_visible_files(self):
        man = json.loads((ROOT / "training" / "canonical" / "manifest.json")
                         .read_text(encoding="utf-8"))
        self.assertEqual(man["model_visible_splits"], ["train"])
        for f in man["files"]:
            self.assertIn(".train.", f["path"], f["path"])
            self.assertTrue((ROOT / f["path"]).is_file(), f["path"])

    def test_the_held_out_shards_are_outside_the_training_directory(self):
        """The excluded rows are kept, but where a corpus consumer cannot see."""
        held = ROOT / "benchmark" / "independent" / "canonical_holdout"
        self.assertTrue(held.is_dir(), "the held-out shards are gone")
        man = json.loads((held / "manifest.json").read_text(encoding="utf-8"))
        self.assertIs(man["MODEL_VISIBLE"], False)
        self.assertGreater(man["excluded_rows"], 0)
        for f in man["files"]:
            path = ROOT / f["path"]
            self.assertTrue(path.is_file(), f["path"])
            self.assertNotIn("training/", f["path"])
        v1 = ROOT / "benchmark" / "independent" / "v1_task_holdout"
        self.assertTrue(v1.is_dir(), "the held-out task rows are gone")
        v1man = json.loads((v1 / "manifest.json").read_text(encoding="utf-8"))
        self.assertIs(v1man["MODEL_VISIBLE"], False)
        self.assertGreater(v1man["excluded_rows"], 0)

    def test_the_manifest_says_where_the_excluded_rows_went(self):
        man = json.loads((ROOT / "training" / "canonical" / "manifest.json")
                         .read_text(encoding="utf-8"))
        held = man["held_out_partitions"]
        self.assertIs(held["model_visible"], False)
        self.assertEqual(held["written_to"],
                         "benchmark/independent/canonical_holdout/")
        self.assertGreater(held["excluded_rows"], 0)


class TestGateIsRunnable(unittest.TestCase):
    def test_the_gate_passes_on_this_tree(self):
        r = subprocess.run(
            [sys.executable, "scripts/check_eval_leakage.py", "--quiet"],
            cwd=str(ROOT), capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_the_private_prove_key_is_not_in_the_tree(self):
        self.assertEqual(gate.check_private_key_absent(), [])

    def test_the_canary_is_not_the_only_defence(self):
        """The gate must measure overlap, not look for a magic string."""
        src = (ROOT / "scripts" / "check_eval_leakage.py").read_text(
            encoding="utf-8")
        self.assertIn("rows_with_id_overlap", src)
        self.assertIn("rows_with_text_overlap", src)
        self.assertIn("rows_with_identical_code_snippet", src)


if __name__ == "__main__":
    unittest.main()
