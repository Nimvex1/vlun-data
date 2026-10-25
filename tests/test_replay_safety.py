"""The rebuild-parity replay writes into the committed layer, so it must be safe.

A replay that is killed between the rebuild and the restore used to leave
`derived/records.jsonl` rebuilt and unpinned, and two overlapping replays
restored each other's snapshots and deleted the committed file. The replay now
takes a lock, keeps a disk backup, and heals an interrupted run on the next
start.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import check_reproducibility as R  # noqa: E402


class FakeGate:
    def __init__(self):
        self.skipped = []
        self.failed = []
        self.passed = []

    def skip(self, name, detail=""):
        self.skipped.append((name, detail))

    def fail(self, name, detail=""):
        self.failed.append((name, detail))

    def ok(self, name, detail=""):
        self.passed.append((name, detail))


class InterruptedReplayHeals(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self._saved = (R.ROOT, R.REPLAY_BACKUP, R.REPLAY_LOCK)
        R.ROOT = self.root
        R.REPLAY_BACKUP = self.root / "work" / ".repro_backup"
        R.REPLAY_LOCK = self.root / "work" / ".repro_replay.lock"

    def tearDown(self):
        R.ROOT, R.REPLAY_BACKUP, R.REPLAY_LOCK = self._saved
        self.tmp.cleanup()

    def test_a_killed_replay_is_healed_from_the_backup(self):
        target = self.root / "derived" / "records.jsonl"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"degraded and unpinned\n")
        R.REPLAY_BACKUP.mkdir(parents=True)
        (R.REPLAY_BACKUP / R._backup_name("derived/records.jsonl")).write_bytes(
            b"committed and pinned\n")
        (R.REPLAY_BACKUP / "ACTIVE.json").write_text(
            json.dumps({"files": ["derived/records.jsonl"],
                        "saved": ["derived/records.jsonl"]}), encoding="utf-8")
        restored = R.recover_interrupted_replay()
        self.assertEqual(restored, ["derived/records.jsonl"])
        self.assertEqual(target.read_bytes(), b"committed and pinned\n")
        self.assertFalse((R.REPLAY_BACKUP / "ACTIVE.json").exists())

    def test_nothing_to_heal_is_not_an_error(self):
        self.assertEqual(R.recover_interrupted_replay(), [])

    def test_a_held_lock_skips_the_replay_instead_of_rebuilding(self):
        R.REPLAY_LOCK.parent.mkdir(parents=True, exist_ok=True)
        R.REPLAY_LOCK.write_text("held", encoding="utf-8")
        target = self.root / "derived" / "records.jsonl"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"committed\n")
        gate = FakeGate()
        result = R.rebuild_parity(gate, "derived/",
                                  [("scripts/build_derived.py", [])],
                                  ["derived/records.jsonl"], [])
        self.assertEqual(result["status"], "skipped")
        self.assertTrue(any("skipped_concurrent_replay" in detail
                            for _, detail in gate.skipped))
        self.assertEqual(target.read_bytes(), b"committed\n")

    def test_a_stale_lock_does_not_block_the_replay(self):
        import os
        import time
        R.REPLAY_LOCK.parent.mkdir(parents=True, exist_ok=True)
        R.REPLAY_LOCK.write_text("old", encoding="utf-8")
        stale = time.time() - (R.REPLAY_LOCK_MAX_AGE_S + 60)
        os.utime(R.REPLAY_LOCK, (stale, stale))
        self.assertFalse(R._replay_lock_held())


if __name__ == "__main__":
    unittest.main()
