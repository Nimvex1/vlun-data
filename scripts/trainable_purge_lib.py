#!/usr/bin/env python3
"""Shared Option A helpers: detect trainable stubs, hydrate from parents, purge.

A row is a METADATA_ONLY_STUB iff the canonical audit classifier says so.
Hydrated rows carry VERBATIM inline snippet+prose copied from a parent record;
nothing is invented. Unhydratable rows are moved to an append-only quarantine
ledger with their full original payload.

Stdlib only. LF writes, sorted keys.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from audit_trainable_vs_metadata import analyze_row  # noqa: E402

PARENT_FILES = (
    "derived/records.jsonl",
    "derived_v2_2/records.jsonl",
    "jsonl/findings.jsonl",
    "jsonl_v3/findings.jsonl",
    "jsonl_v4/findings.jsonl",
    "Vbeta/derived_vbeta/records.jsonl",
    "derived_v3/records.jsonl",
)
ID_KEYS = ("finding_id", "record_id", "candidate_id", "id", "original_id", "task_id")


def is_stub(row: dict) -> bool:
    return analyze_row(row, set())["bucket"] == "METADATA_ONLY_STUB"


def _inline(row: dict) -> tuple[str, str]:
    """Return (verbatim code, verbatim prose) available in a parent row."""
    code = ""
    prose = ""
    ctx = row.get("code_context")
    if isinstance(ctx, list):
        for c in ctx:
            if isinstance(c, dict):
                s = str(c.get("snippet") or c.get("code") or "")
                if len(s) > len(code):
                    code = s
    for key in ("description", "description_long", "root_cause", "summary",
                "attack_sequence", "verification_evidence"):
        v = row.get(key)
        if isinstance(v, str) and len(v) > len(prose):
            prose = v
    return code, prose


def parent_index() -> dict[str, dict]:
    out: dict[str, dict] = {}
    for rel in PARENT_FILES:
        p = ROOT / rel
        if not p.is_file():
            continue
        for line in p.open(encoding="utf-8", errors="replace"):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if not isinstance(row, dict):
                continue
            for key in ID_KEYS:
                val = row.get(key)
                if isinstance(val, str) and val and val not in out:
                    out[val] = row
    return out


def hydrate_from_parent(row: dict, parents: dict[str, dict]) -> bool:
    """Add verbatim parent code+prose into the row's input/evidence. Mutates row.

    Returns True when the row now classifies as non-stub.
    """
    ids = [str(row.get(k)) for k in ID_KEYS if isinstance(row.get(k), str)]
    src = None
    for key in ID_KEYS:
        val = row.get(key)
        if isinstance(val, str) and val in parents:
            src = parents[val]
            break
    if src is None:
        # nested id carriers: input.finding_id / source.record_id
        for container in ("input", "source", "provenance"):
            c = row.get(container)
            if isinstance(c, dict):
                for key in ID_KEYS:
                    val = c.get(key)
                    if isinstance(val, str) and val in parents:
                        src = parents[val]
                        break
            if src is not None:
                break
    if src is None:
        return False
    code, prose = _inline(src)
    if len(code) < 50 or len(prose) < 100:
        return False
    target = row.setdefault("input", {}) if isinstance(row.get("input"), dict) else row
    if isinstance(target, dict):
        target.setdefault("inline_code", code[:6000])
        target.setdefault("inline_prose", prose[:6000])
    return not is_stub(row)


def enforce_trainable(rows: list[dict], source_table: str, id_keys: tuple[str, ...] = ("id",),
                      parents: dict[str, dict] | None = None) -> tuple[list[dict], list[dict]]:
    """Builder-side hook: hydrate stub rows from parents, quarantine the rest.

    Returns ``(kept_rows, purged_quarantine_rows)``. Builders call this on the
    rows they are about to write so `--check` recomputation matches the purged
    committed file. The caller writes the quarantine rows to its own ledger.
    """
    if parents is None:
        parents = parent_index()
    kept: list[dict] = []
    purged: list[dict] = []
    for row in rows:
        if not is_stub(row):
            kept.append(row)
            continue
        hydrate_from_parent(row, parents)
        if is_stub(row):
            rid = next((str(row[k]) for k in id_keys
                        if isinstance(row.get(k), str) and row.get(k)), str(id(row)))
            purged.append(quarantine_payload(row, source_table, rid))
        else:
            kept.append(row)
    return kept, purged


def quarantine_payload(row: dict, source_table: str, row_id: str) -> dict:
    return {
        "id": row_id,
        "record_id": row_id,
        "reason": "UNHYDRATABLE_DEAD_POINTER",
        "source_table": source_table,
        "record": row,
    }


def append_quarantine(path: Path, rows: list[dict]) -> int:
    existing: list[dict] = []
    if path.is_file():
        for line in path.open(encoding="utf-8", errors="replace"):
            if line.strip():
                try:
                    existing.append(json.loads(line))
                except ValueError:
                    pass
    seen = {(r.get("source_table"), r.get("id")) for r in existing}
    merged = list(existing)
    for row in rows:
        key = (row.get("source_table"), row.get("id"))
        if key not in seen:
            merged.append(row)
            seen.add(key)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        for row in merged:
            fh.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
    return len(merged)
