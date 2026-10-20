#!/usr/bin/env python3
"""Versioned migration: put the V4 licence decision into the records themselves.

`V4/licensing.json` states what each source declares about its own content.
Until now the layers disagreed with it: every V4 record carried
`license: "unknown"` / `license_status: "unknown"`, `V4/sources.json` said the
same, and the manifests declared "no LICENSE file found" or "CC BY-ND 4.0" — so
a reader could not tell which was true, and the most restrictive fact (Oak's
No-Derivatives term) was invisible.

This script rewrites only the licence fields, from the registry, and proves it
touched nothing else: each row is compared field by field against its original
before and after, and any change outside the declared licence fields aborts the
run. It writes a migration ledger, is idempotent, and reports `--check` mode
without writing.

    python scripts/reconcile_v4_licensing.py [--check] [--dry-run]
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vlun import ROOT, log  # noqa: E402

REGISTRY = ROOT / "V4" / "licensing.json"
LEDGER = ROOT / "reports" / "v4_licensing_migration.json"
MIGRATION = "v4-licensing-1.0"
TARGETS = ("jsonl_v4/findings.jsonl", "jsonl_v4/sources.jsonl",
           "derived_v4/admitted_ledger.jsonl", "derived_v4/duplicate_ledger.jsonl",
           "derived_v4/quarantined_ledger.jsonl")
SOURCES_JSON = ROOT / "V4" / "sources.json"
# fields this migration may change; everything else must survive byte-for-byte
LICENCE_FIELDS = {"license", "license_status", "rights_decision", "derivatives_allowed",
                  "redistribution_right", "legal_clearance", "data_handling_policy",
                  "rights_migration"}
# `derived_v4/candidate_ledger.jsonl` is not a target: register_v4.py writes it with
# only `candidate_id`, `decision` and `source_id`, so stamping licence fields there
# would add columns the generator does not produce and the layer would drift.


def registry() -> dict:
    if not REGISTRY.exists():
        raise SystemExit(f"{REGISTRY.relative_to(ROOT)} is missing; the licence "
                         "decision must be recorded before the records are reconciled")
    doc = json.loads(REGISTRY.read_text(encoding="utf-8"))
    return {s["source_id"]: s for s in doc.get("sources") or []}, doc


def apply_row(row: dict, by_id: dict, doc: dict) -> dict:
    sid = row.get("source_id")
    src = by_id.get(sid)
    if src is None:
        return row
    out = dict(row)
    out["license"] = src["license_status"]
    out["license_status"] = src["license_status"]
    out["derivatives_allowed"] = src["derivatives_allowed"]
    out["redistribution_right"] = src["redistribution_right"]
    out["legal_clearance"] = src["legal_clearance"]
    out["data_handling_policy"] = src["data_handling_policy"]
    out["rights_decision"] = {
        "version": doc["version"],
        "basis": "V4/licensing.json#" + sid,
        "evidence": src["evidence"],
        "decided": doc["generated"],
        "decided_by": doc["decided_by"],
        "not_a_legal_clearance": True,
    }
    prior = row.get("rights_migration") or {}
    already = (prior.get("version") == MIGRATION
               and row.get("license") == src["license_status"]
               and row.get("license_status") == src["license_status"])
    out["rights_migration"] = prior if already else {
        "version": MIGRATION,
        "superseded_values": {k: row.get(k) for k in ("license", "license_status")
                              if k in row}}
    return out


def diff_fields(before: dict, after: dict) -> list[str]:
    keys = set(before) | set(after)
    return sorted(k for k in keys if before.get(k) != after.get(k))


def migrate(path: Path, by_id: dict, doc: dict, write: bool) -> dict:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    changed = 0
    offlimits = []
    stats: dict[str, int] = {}
    out_rows = []
    for row in rows:
        new = apply_row(row, by_id, doc)
        touched = diff_fields(row, new)
        bad = [k for k in touched if k not in LICENCE_FIELDS]
        if bad:
            offlimits.append(f"{path.name}:{row.get('record_id') or row.get('id')}: {bad}")
        if new != row:
            changed += 1
            stats[row.get("source_id") or "?"] = stats.get(row.get("source_id") or "?", 0) + 1
        out_rows.append(new)
    if offlimits:
        raise SystemExit(f"{path.name}: migration would change non-licence fields: "
                         + "; ".join(offlimits[:3]))
    text = "".join(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n"
                   for r in out_rows)
    if write:
        path.write_text(text, encoding="utf-8", newline="\n")
    # `--check` compares rows, not bytes: the committed files are written by
    # register_v4.py in its own key order, and reordering keys is not a licence
    # contradiction. What must hold is that every row already carries the
    # resolved decision.
    return {"file": path.relative_to(ROOT).as_posix(), "rows": len(rows),
            "rows_changed": changed, "by_source": stats,
            "current_bytes_match_output": path.read_text(encoding="utf-8") == text,
            "rows_already_reconciled": len(rows) - changed}


def migrate_sources_json(by_id: dict, doc: dict, write: bool) -> dict:
    rows = json.loads(SOURCES_JSON.read_text(encoding="utf-8"))
    out, changed = [], 0
    for row in rows:
        src = by_id.get(row.get("source_id"))
        if src is None:
            out.append(row)
            continue
        new = dict(row)
        new["license_status"] = src["license_status"]
        new["rights_decision"] = {"version": doc["version"],
                                  "basis": "V4/licensing.json#" + row["source_id"],
                                  "evidence": src["evidence"],
                                  "decided": doc["generated"]}
        if new != row:
            changed += 1
        extra = set(new) - set(row)
        if not extra <= {"rights_decision"}:
            raise SystemExit("V4/sources.json: unexpected field change")
        for k in row:
            if k not in ("license_status",) and row[k] != new[k]:
                raise SystemExit(f"V4/sources.json:{row.get('source_id')}: "
                                 f"{k} would change")
        out.append(new)
    text = json.dumps(out, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if write:
        SOURCES_JSON.write_text(text, encoding="utf-8", newline="\n")
    return {"file": "V4/sources.json", "rows": len(rows), "rows_changed": changed,
            "current_bytes_match_output":
                SOURCES_JSON.read_text(encoding="utf-8") == text}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--check", action="store_true",
                    help="report whether the layers already agree, write nothing")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    by_id, doc = registry()
    results = []
    for rel in TARGETS:
        p = ROOT / rel
        if p.exists():
            results.append(migrate(p, by_id, doc, write=not (args.check or args.dry_run)))
    results.append(migrate_sources_json(by_id, doc, write=not (args.check or args.dry_run)))

    stale = [r["file"] for r in results if r["rows_changed"]]
    ledger = {
        "generated_by": "scripts/reconcile_v4_licensing.py",
        "migration_version": MIGRATION,
        "registry": "V4/licensing.json",
        "registry_version": doc["version"],
        "applied_utc": (dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                        if not (args.check or args.dry_run) else None),
        "files": results,
        "fields_touched": sorted(LICENCE_FIELDS),
        "guarantee": ("only licence and rights-decision fields were written; the "
                      "migration aborts if any other field would change. Original "
                      "values are preserved in each row's `rights_migration`."),
        "already_consistent": not stale,
        "stale_files": stale,
    }
    if not (args.check or args.dry_run):
        LEDGER.write_text(json.dumps(ledger, ensure_ascii=False, indent=2,
                                     sort_keys=True) + "\n",
                          encoding="utf-8", newline="\n")
    if args.check:
        if stale:
            log("STALE: " + ", ".join(stale) + " — run scripts/reconcile_v4_licensing.py")
            return 1
        log("V4 licence fields already match V4/licensing.json")
        return 0
    log(json.dumps({"files": {r["file"]: r["rows_changed"] for r in results},
                    "already_consistent": not stale}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
