"""The clean holdout must carry zero literal-answer overlap, and that claim is
recomputed here rather than read out of the manifest.

The key file is local-only, so this test skips the overlap recomputation when it
is absent (a fresh checkout) and still checks the structural claims.
"""
import json
import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import independent_benchmark_audit as audit  # noqa: E402

INDEP = ROOT / "benchmark" / "independent"
CLEAN_TASKS = INDEP / "secondary_holdout_tasks.jsonl"
EXPLORATORY_TASKS = INDEP / "secondary_holdout_exploratory_tasks.jsonl"
CLEAN_KEYS = INDEP / "secondary_holdout_keys.jsonl"
EXPLORATORY_KEYS = INDEP / "secondary_holdout_exploratory_keys.jsonl"
MANIFEST = INDEP / "secondary_holdout_manifest.json"
FORBIDDEN_KEY_FIELDS = ("gold", "label", "answer", "answer_key", "expected",
                         "original_id", "original_split", "group", "split",
                         "key_status", "partition")


def rows(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in
            path.read_text(encoding="utf-8").splitlines() if line.strip()]


def answer_pattern(gold: str) -> re.Pattern | None:
    if not gold or not isinstance(gold, str) or gold in ("true", "false") or len(gold) < 3:
        return None
    return re.compile(r"(?<![a-z0-9])" + re.escape(gold) + r"(?![a-z0-9])", re.IGNORECASE)


def evidence_leaves(value, path=(), top=False):
    """Every string the audit's own evidence_text reads, re-derived here.

    Instruction scaffolding (the prompt, the label vocabulary) names the answer
    space and is not evidence; every other string in the payload is.
    """
    if isinstance(value, dict):
        for key, item in value.items():
            if top and key in audit.INSTRUCTION_KEYS:
                continue
            if key in audit.DROP_KEYS:
                continue
            yield from evidence_leaves(item, path + (key,), False)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from evidence_leaves(item, path + (index,), False)
    elif isinstance(value, str):
        yield path, value


def leaks(input_obj: dict, gold) -> list[str]:
    pattern = answer_pattern(gold)
    if pattern is None:
        return []
    found = []
    for path, text in evidence_leaves(input_obj, (), True):
        if pattern.search(text):
            found.append(".".join(str(p) for p in path))
    return found


class TestSecondaryHoldout(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        cls.clean = rows(CLEAN_TASKS)
        cls.exploratory = rows(EXPLORATORY_TASKS)
        cls.keys = rows(CLEAN_KEYS)
        cls.exploratory_keys = rows(EXPLORATORY_KEYS)

    def test_the_builder_reproduces_the_committed_layer(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "build_secondary_holdout.py"), "--check"],
            cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_the_clean_partition_has_zero_literal_answer_overlap(self):
        if not self.keys:
            self.skipTest("the answer key is local-only and absent in this checkout")
        by_id = {k["holdout_task_id"]: k for k in self.keys}
        self.assertEqual(len(by_id), len(self.clean))
        offenders = []
        for task in self.clean:
            key = by_id.get(task["holdout_task_id"])
            self.assertIsNotNone(key, task["holdout_task_id"])
            found = leaks(task["input"], key.get("gold"))
            if found:
                offenders.append((task["holdout_task_id"], task["family_file"], found[:2]))
        self.assertEqual(offenders, [], f"literal answer overlap in the clean holdout: {offenders[:5]}")

    def test_the_manifest_claim_matches_the_recomputation(self):
        claim = self.manifest["clean_holdout"]
        self.assertEqual(claim["literal_answer_overlap"], 0)
        self.assertEqual(claim["rows"], len(self.clean))
        if self.keys:
            by_id = {k["holdout_task_id"]: k for k in self.keys}
            recomputed = sum(1 for task in self.clean
                             if leaks(task["input"], by_id[task["holdout_task_id"]].get("gold")))
            self.assertEqual(recomputed, 0)

    def test_clean_tasks_carry_no_answer_key_or_hidden_identifiers(self):
        for task in self.clean:
            for field in FORBIDDEN_KEY_FIELDS:
                self.assertNotIn(field, task, f"{task['holdout_task_id']} carries {field}")
                self.assertNotIn(field, task["input"],
                                 f"{task['holdout_task_id']} input carries {field}")

    def test_the_exploratory_partition_is_disjoint_and_labelled_as_such(self):
        clean_ids = {t["holdout_task_id"] for t in self.clean}
        exploratory_ids = {t["holdout_task_id"] for t in self.exploratory}
        self.assertFalse(clean_ids & exploratory_ids)
        claim = self.manifest["exploratory_holdout"]
        self.assertEqual(claim["rows"], len(self.exploratory))
        self.assertIn("EXPLORATORY", claim["claim"])
        self.assertIn("not independent", claim["claim"])

    def test_contaminated_rows_are_counted_by_recomputation(self):
        if not self.exploratory_keys:
            self.skipTest("the exploratory key file is local-only and absent here")
        by_id = {k["holdout_task_id"]: k for k in self.exploratory_keys}
        contaminated = sum(1 for task in self.exploratory
                           if leaks(task["input"], by_id[task["holdout_task_id"]].get("gold")))
        self.assertEqual(contaminated, self.manifest["exploratory_holdout"]["contaminated_rows"])

    def test_the_key_tracking_claim_matches_git(self):
        # The manifest must describe the key as git actually has it: tracked in
        # a local commit, or untracked. Either way it is not a secret.
        key_block = self.manifest["answer_key"]
        self.assertEqual(key_block["key_status"], "OPEN_KEY")
        tracked = subprocess.run(
            ["git", "ls-files", "--error-unmatch",
             "benchmark/independent/secondary_holdout_keys.jsonl"],
            cwd=ROOT, capture_output=True, text=True).returncode == 0
        self.assertIs(key_block["committed_in_repository"], tracked)
        self.assertIs(key_block["tracked_in_git"], tracked)
        self.assertIn("never be described as a private", key_block["implication"])

    def test_every_redaction_is_recorded_without_the_answer_text(self):
        for record in self.manifest.get("transforms") or []:
            self.assertIn("field", record)
            self.assertIn("before_sha256", record)
            self.assertIn("after_sha256", record)
            self.assertNotIn("gold", record)
            self.assertNotIn("answer", record)


if __name__ == "__main__":
    unittest.main()
