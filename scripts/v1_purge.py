#!/usr/bin/env python3
"""Enforce FULLY_TRAINABLE on v1 model-visible tables (stdlib only).

A row that is not FULLY_TRAINABLE (inline code >=50 chars AND inline prose
>=100 chars, per scripts/audit_trainable_vs_metadata.py) is REMOVED from the
model-visible table and copied, with the v1 full-record marker triple, into
``datasets/v1_hydration_quarantine.jsonl``. The ledger copy keeps the original
finding/candidate id and the reason ``UNHYDRATABLE_DEAD_POINTER`` so the row
accounting stays reconstructible.

Governed bookkeeping rows (record_type protocol/error/metadata/ledger) are
never purged: those ledgers are allowed to hold metadata records.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from vlun import read_jsonl, write_jsonl  # noqa: E402
import audit_trainable_vs_metadata as audit  # noqa: E402

QUARANTINE = ROOT / "datasets" / "v1_hydration_quarantine.jsonl"
REASON = "UNHYDRATABLE_DEAD_POINTER"
GOVERNED_RECORD_TYPES = {"protocol", "error", "metadata", "ledger", "metadata_only"}


def bucket(row: dict) -> str:
    return audit.analyze_row(row, set())["bucket"]


def is_governed(row: dict) -> bool:
    return str(row.get("record_type") or "").strip().lower() in GOVERNED_RECORD_TYPES


def original_id(row: dict):
    return (
        (row.get("finding") or {}).get("id")
        or row.get("finding_id")
        or row.get("canonical_record_id")
        or row.get("id")
    )


def is_trainable(row: dict) -> bool:
    """FULLY_TRAINABLE, or a governed bookkeeping record (kept by policy)."""
    return is_governed(row) or bucket(row) == "FULLY_TRAINABLE"


def has_negative_triple(row: dict) -> bool:
    """verified_negatives rows must carry claim + triage + disputed code."""
    return bool(
        str(row.get("original_claim_body") or "").strip()
        and str(row.get("triage_prose") or "").strip()
        and row.get("disputed_code_context")
    )


def quarantine_copy(row: dict, source_file: str, reason: str = REASON) -> dict:
    q = dict(row)
    q["_quarantine_reason"] = reason
    q["_quarantined_from_split"] = "unset"
    q["_v1_hydration_setaside_reason"] = reason
    q["_quarantine_source_file"] = source_file
    q["_quarantine_evidence"] = {
        "detector": "v1_trainable_enforcement",
        "reason": reason,
        "id": original_id(row),
        "source_file": source_file,
    }
    return q


def load_ledger() -> dict:
    if not QUARANTINE.exists():
        return {}
    out = {}
    for row in read_jsonl(QUARANTINE):
        ev = row.get("_quarantine_evidence") or {}
        key = (
            ev.get("id") or row.get("_quarantine_id") or original_id(row),
            ev.get("source_file") or row.get("_quarantine_source_file") or "",
        )
        out[key] = row
    return out


def save_ledger(ledger: dict) -> None:
    QUARANTINE.parent.mkdir(parents=True, exist_ok=True)
    rows = [ledger[k] for k in sorted(ledger, key=lambda t: (str(t[0]), str(t[1])))]
    write_jsonl(QUARANTINE, rows)


def enforce_list(rows: list, source_file: str, *, negative_triple: bool = False,
                 ledger: dict | None = None) -> tuple[list, dict]:
    """Return (kept rows, ledger). Purged rows are appended to the ledger.

    ``ledger`` may be passed to batch several files into one save; when it is
    None the on-disk ledger is loaded and saved here.
    """
    own = ledger is None
    led = load_ledger() if own else ledger
    kept, purged = [], []
    for row in rows:
        bad = not is_trainable(row)
        if negative_triple and not bad:
            bad = not has_negative_triple(row)
        key = (original_id(row), source_file)
        if bad:
            led.setdefault(key, quarantine_copy(row, source_file))
            purged.append(row)
        else:
            # A row that is now trainable must not linger in the quarantine
            # ledger from an earlier (pre-hydration) run of this builder.
            led.pop(key, None)
            kept.append(row)
    if own:
        save_ledger(led)
    return kept, led


def enforce_file(path: Path, *, negative_triple: bool = False,
                 ledger: dict | None = None) -> tuple[int, int, int, dict]:
    rows = read_jsonl(path) if path.exists() else []
    rel = path.relative_to(ROOT).as_posix() if path.is_absolute() else str(path)
    kept, led = enforce_list(rows, rel, negative_triple=negative_triple, ledger=ledger)
    if len(kept) != len(rows):
        write_jsonl(path, kept)
    return len(rows), len(kept), len(rows) - len(kept), led
