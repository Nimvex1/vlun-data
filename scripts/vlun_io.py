#!/usr/bin/env python3
"""Canonical JSON/JSONL and hashing primitives for every VLUN layer.

Before this module existed, ``read_jsonl``/``write_jsonl``/``write_json``/
``sha256_text``/``sha256_file`` were copied into ``vlun.py``, ``vlun_ml.py``,
``vlun_v3.py`` and ``audit_sources.py`` -- and the copies had already drifted:
``vlun_v3.read_jsonl`` tolerated a missing file and wrote non-atomically while
the others raised and wrote atomically. Both behaviours are legitimate, so this
module names them explicitly instead of letting each layer pick by accident:

    read_jsonl(path)                    raise if the file is missing (default)
    read_jsonl(path, missing_ok=True)   return [] when the file is absent
    read_jsonl(path, strict=True)       raise ValueError on a malformed row

Writes are always atomic (temp file + ``replace``) and always LF, so a build
cannot leave a half-written layer behind and output is platform-stable.

This module imports nothing from ``scripts/``, so every layer can import it
without creating a cycle.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


def read_jsonl(path: Path, *, missing_ok: bool = False,
               strict: bool = True) -> list[dict]:
    """Read a JSONL file into a list of objects.

    ``missing_ok`` turns a missing file into ``[]`` (v3 ledger behaviour);
    ``strict=False`` tolerates a malformed row instead of raising.
    """
    rows: list[dict] = []
    if missing_ok and not path.exists():
        return rows
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            if strict:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"{path.name}:{lineno} invalid JSON: {exc}") from exc
            else:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return rows


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    tmp.replace(path)


def write_jsonl(path: Path, rows: list[dict]) -> None:
    """Write rows as canonical JSONL: sorted keys, one object per line, LF."""
    _atomic_write(path, "".join(
        json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n"
        for row in rows))


def write_json(path: Path, obj) -> None:
    """Write an object as canonical JSON: indent 2, sorted keys, trailing LF."""
    _atomic_write(
        path,
        json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def claim(value, etype: str, rule: str | None = None, refs=None,
          note: str | None = None) -> dict:
    """Evidence wrapper whose pointer cannot be forgotten.

    `rule` names the producing rule as ``rule:<module>:<function>`` and is
    always stored in ``source_refs`` (first position); extra `refs` (URLs,
    ids) follow. A fact-typed wrapper built without `rule` carries an empty
    list, which the pointer gate rejects — the call site must name its rule.
    Deliberately unvalidated: vocabulary enforcement belongs to the
    validators (schema_terms), not to construction.
    """
    d = {"value": value if value not in ("", None) else None,
         "evidence_type": etype,
         "source_refs": ([rule] if rule else []) + list(refs or [])}
    if note:
        d["note"] = note
    return d


__all__ = [
    "claim", "read_jsonl", "sha256_bytes", "sha256_file", "sha256_text",
    "write_json", "write_jsonl",
]