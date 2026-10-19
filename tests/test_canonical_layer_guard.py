"""Whole-tree rebuild must not quietly rewrite published data (spec item 10).

Two guards, both engineered so they FAIL against the broken behaviour they were
written after:

  * `build_all.py` re-runs every generator, and a stage-ordering difference can
    land on `derived/` or `splits_v2/` — bytes consumers, splits and citations
    are pinned to. The guard restores those bytes and reports the attempt; a
    real refresh is an explicit `--allow-canonical-rewrite` migration. A guard
    that logs but leaves the new bytes in place is the failure mode, so the test
    asserts the file content is the original.
  * `benchmark/manifest.json` is written by two builders in sequence. The A-J
    pass used to rebuild the dict from scratch and delete the K-Q bookkeeping,
    including the record that six families were retired — and because the
    retired entries were only ever carried from that same file, the loss was
    unrecoverable. The builders now carry foreign entries and raise instead of
    dropping.
"""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import build_all as A  # noqa: E402

RETIRED = ["B_root_cause_reasoning", "E_exploit_verification",
           "K_language_ecosystem_routing", "L_severity_reconciliation",
           "M_experiment_level_classification", "N_attacker_identity_extraction",
           "O_record_class_and_scope", "P_provenance_tier_and_rights"]


class CanonicalLayerGuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self._real_root = A.ROOT
        A.ROOT = self.root
        self.rel = "derived/records.jsonl"
        p = self.root / self.rel
        p.parent.mkdir(parents=True, exist_ok=True)
        self.original = b'{"id": "x", "level": "L5"}\n'
        p.write_bytes(self.original)
        self.start = {self.rel: self.original}

    def tearDown(self):
        A.ROOT = self._real_root

    def _sha(self, blob: bytes) -> str:
        return hashlib.sha256(blob).hexdigest()

    def test_rewrite_is_restored_and_reported(self):
        (self.root / self.rel).write_bytes(b'{"id": "x", "level": "L3"}\n')
        blocked = A.guard_canonical_layers(7, "some_stage.py", self.start, False)
        self.assertEqual([rel for rel, _ in blocked], [self.rel])
        rec = blocked[0][1]
        self.assertEqual(rec["stage"], 7)
        self.assertEqual(rec["before"], self._sha(self.original))
        self.assertTrue(rec["restored"])
        # the crux: the published bytes survive, they are not merely reported
        self.assertEqual((self.root / self.rel).read_bytes(), self.original)

    def test_untouched_layer_is_not_flagged(self):
        self.assertEqual(A.guard_canonical_layers(
            7, "some_stage.py", self.start, False), [])

    def test_explicit_migration_keeps_the_new_bytes(self):
        new = b'{"id": "x", "level": "L4"}\n'
        (self.root / self.rel).write_bytes(new)
        blocked = A.guard_canonical_layers(9, "migrate.py", self.start, True)
        self.assertFalse(blocked[0][1]["restored"])
        self.assertEqual((self.root / self.rel).read_bytes(), new)

    def test_deleted_layer_is_restored(self):
        (self.root / self.rel).unlink()
        blocked = A.guard_canonical_layers(7, "some_stage.py", self.start, False)
        self.assertTrue(blocked)
        self.assertEqual((self.root / self.rel).read_bytes(), self.original)

    def test_guard_covers_the_published_layers_by_name(self):
        for rel in ("derived/records.jsonl", "splits_v2/quarantine.jsonl",
                    "reports/leakage_report.json"):
            self.assertIn(rel, A.CANONICAL_LAYERS)


class ForeignManifestEntryTests(unittest.TestCase):
    def test_foreign_entries_survive_a_full_rewrite(self):
        from vlun import carry_foreign_task_entries
        prev = {"tasks": {"A_vulnerability_detection": {"status": "headline"},
                          "K_language_ecosystem_routing": {"status": "retired",
                                                           "tasks": 137}}}
        manifest = {"tasks": {}}
        carried = carry_foreign_task_entries(manifest, prev,
                                            {"A_vulnerability_detection"})
        self.assertEqual(carried, ["K_language_ecosystem_routing"])
        self.assertEqual(manifest["tasks"]["K_language_ecosystem_routing"],
                         {"status": "retired", "tasks": 137})

    def test_own_entries_are_not_carried_and_get_rebuilt(self):
        from vlun import carry_foreign_task_entries
        prev = {"tasks": {"A_vulnerability_detection": {"tasks": 999}}}
        manifest = {"tasks": {}}
        carry_foreign_task_entries(manifest, prev, {"A_vulnerability_detection"})
        self.assertEqual(manifest["tasks"], {},
                         "a builder must not pre-seed the families it writes")


class PublishedManifestTests(unittest.TestCase):
    def test_committed_manifest_still_lists_every_family(self):
        man = json.loads((ROOT / "benchmark" / "manifest.json")
                         .read_text(encoding="utf-8"))
        for name in RETIRED:
            self.assertIn(name, man["families"],
                          f"{name} dropped from the manifest: the retirement "
                          "bookkeeping is gone")
            self.assertEqual(man["tasks"][name]["status"], "retired")

    def test_retired_families_have_on_disk_records_pointed_at(self):
        man = json.loads((ROOT / "benchmark" / "manifest.json")
                         .read_text(encoding="utf-8"))
        for name in RETIRED:
            entry = man["tasks"][name]
            self.assertTrue((ROOT / entry["file"]).is_file(),
                            f"{name}: manifest points at a missing file")
            with open(ROOT / entry["file"], encoding="utf-8") as fh:
                rows = sum(1 for line in fh if line.strip())
            self.assertEqual(entry["tasks"], rows,
                             f"{name}: manifest row count disagrees with the "
                             "frozen data")


if __name__ == "__main__":
    unittest.main()
