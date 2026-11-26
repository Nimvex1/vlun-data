#!/usr/bin/env python3
"""Option A: drive every trainable/benchmark JSONL table to 0 metadata stubs.

For each configured table:
  1. hydrate stub rows from verbatim parent records (local clones / canonical
     layers) using scripts/trainable_purge_lib.py;
  2. move every remaining unhydratable stub to an append-only quarantine
     ledger with its full original payload (no fabrication, nothing lost);
  3. rewrite the table preserving its existing JSON serialization style.

Run: python scripts/purge_trainable_stubs.py [--check]
Stdlib only.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from trainable_purge_lib import (  # noqa: E402
    ROOT as LIB_ROOT, is_stub, parent_index, hydrate_from_parent,
    quarantine_payload, append_quarantine,
)

# (table, quarantine ledger, id keys in priority order, paired task table for keys)
CONFIG: list[tuple[str, str, tuple[str, ...], str | None]] = [
    ("benchmark/v3_R_source_tier_routing.jsonl",
     "quarantine/benchmark_v3_R_quarantine.jsonl", ("task_id",), None),
    ("benchmark/independent/secondary_holdout_keys.jsonl",
     "quarantine/secondary_holdout_quarantine.jsonl",
     ("holdout_task_id",), "benchmark/independent/secondary_holdout_tasks.jsonl"),
    ("benchmark/independent/secondary_holdout_tasks.jsonl",
     "quarantine/secondary_holdout_quarantine.jsonl",
     ("holdout_task_id",), None),
    ("benchmark/independent/secondary_holdout_exploratory_keys.jsonl",
     "quarantine/secondary_holdout_quarantine.jsonl",
     ("holdout_task_id",), "benchmark/independent/secondary_holdout_exploratory_tasks.jsonl"),
    ("derived_poc_queue/triage_queue.jsonl",
     "derived_poc_queue/quarantine.jsonl", ("candidate_id", "finding_id"), None),
    ("benchmark/retired_families/E_exploit_verification.jsonl",
     "quarantine/retirement_quarantine.jsonl", ("task_id",), None),
    ("benchmark/retired_families/v3_S_contest_outcome.jsonl",
     "quarantine/retirement_quarantine.jsonl", ("task_id",), None),
    ("taxonomy/assignments_v1.jsonl",
     "taxonomy/quarantine.jsonl", ("record_id",), None),
    ("annotation/iaa_v1/sample.jsonl",
     "annotation/iaa_v1/quarantine.jsonl", ("record_id",), None),
    ("training/canonical/detection.train.part-000.jsonl",
     "training/canonical/quarantine.jsonl", ("record_id", "finding_id"), None),
    ("training/canonical/language.train.part-000.jsonl",
     "training/canonical/quarantine.jsonl", ("record_id", "finding_id"), None),
    ("training/canonical/language.train.part-001.jsonl",
     "training/canonical/quarantine.jsonl", ("record_id", "finding_id"), None),
    ("training/canonical/severity.train.part-000.jsonl",
     "training/canonical/quarantine.jsonl", ("record_id", "finding_id"), None),
    ("training/canonical/severity.train.part-001.jsonl",
     "training/canonical/quarantine.jsonl", ("record_id", "finding_id"), None),
    ("benchmark/independent/canonical_holdout/detection.heldout.part-000.jsonl",
     "quarantine/canonical_holdout_quarantine.jsonl", ("record_id", "finding_id"), None),
    ("benchmark/independent/canonical_holdout/language.heldout.part-000.jsonl",
     "quarantine/canonical_holdout_quarantine.jsonl", ("record_id", "finding_id"), None),
    ("benchmark/independent/canonical_holdout/severity.heldout.part-000.jsonl",
     "quarantine/canonical_holdout_quarantine.jsonl", ("record_id", "finding_id"), None),
    ("derived/counterexamples.jsonl",
     "derived/quarantine_counterexamples.jsonl", ("counterexample_id", "id"), None),
    ("derived_v3/records.jsonl",
     "derived_v3/quarantine.jsonl", ("finding_id",), None),
    ("derived_v3/normalized_records_preview.jsonl",
     "derived_v3/quarantine.jsonl", ("finding_id",), None),
]


def read_rows(path: Path) -> list[dict]:
    out = []
    for line in path.open(encoding="utf-8", errors="replace"):
        if line.strip():
            out.append(json.loads(line))
    return out


def serialise(rows: list[dict], sample_path: Path) -> str:
    """Mirror the existing file's key order / sorted style."""
    first = sample_path.read_text(encoding="utf-8").splitlines()[0] if sample_path.exists() else ""
    keys = list(json.loads(first).keys()) if first else []
    ordered = all(list(r.keys()) == keys for r in rows)
    if ordered:
        return "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows)
    return "".join(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n" for r in rows)


def row_id(row: dict, keys: tuple[str, ...]) -> str:
    for key in keys:
        val = row.get(key)
        if isinstance(val, str) and val:
            return val
    return str(row.get("task_id") or row.get("record_id") or id(row))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    def stub(row: dict) -> bool:
        # Verbatim-hydrated rows carry a HYDRATED status from the layer's own
        # hydration pass; skip reclassification of their multi-KB snippets.
        hyd = row.get("_hydration") or {}
        if isinstance(hyd, dict) and str(hyd.get("status", "")).startswith("HYDRATED"):
            return False
        return is_stub(row)

    parents = parent_index()
    totals = {"stubs_before": 0, "hydrated": 0, "purged": 0, "stubs_after": 0}
    report = {}
    for rel, qrel, id_keys, pair_rel in CONFIG:
        path = ROOT / rel
        if not path.is_file():
            continue
        rows = read_rows(path)
        before = sum(1 for r in rows if stub(r))
        if not before:
            continue

        paired = {}
        if pair_rel and (ROOT / pair_rel).is_file():
            for r in read_rows(ROOT / pair_rel):
                tid = r.get("holdout_task_id") or r.get("task_id")
                if isinstance(tid, str):
                    paired[tid] = r

        kept, purged = [], []
        hydrated = 0
        for row in rows:
            if not stub(row):
                kept.append(row)
                continue
            # Answer-key rows: a verbatim snapshot of the paired task's input
            # is real inline content (never invented).
            tid = row.get("holdout_task_id")
            if paired and isinstance(tid, str) and tid in paired:
                task_input = paired[tid].get("input")
                if isinstance(task_input, dict):
                    row["input"] = task_input
            if stub(row):
                hydrate_from_parent(row, parents)
            if stub(row):
                purged.append(quarantine_payload(row, rel, row_id(row, id_keys)))
            else:
                hydrated += 1
                kept.append(row)

        after = sum(1 for r in kept if stub(r))
        totals["stubs_before"] += before
        totals["hydrated"] += hydrated
        totals["purged"] += len(purged)
        totals["stubs_after"] += after
        report[rel] = {"before": before, "hydrated": hydrated,
                       "purged": len(purged), "after": after}
        if not args.check:
            path.write_text(serialise(kept, path), encoding="utf-8", newline="\n")
            qpath = ROOT / qrel
            qtotal = append_quarantine(qpath, purged)
            report[rel]["quarantine_rows"] = qtotal

    print(json.dumps({"check": args.check, "totals": totals, "files": report},
                     indent=2, sort_keys=True, ensure_ascii=False))
    return 1 if totals["stubs_after"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
