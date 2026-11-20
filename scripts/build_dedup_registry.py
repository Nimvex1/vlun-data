#!/usr/bin/env python3
"""Build the cross-layer dedup registry (Step 2/3 input).

Read-only: scans the five existing layers with inventory_dedup.py's
machinery and writes ``work/dedup_registry.json`` with, per layer:

  * ``urls``: sorted unique normalized URLs
  * ``digests``: sorted unique 64-hex sha256 digests
  * ``keys``: sorted ``[auditor_or_org, protocol_or_repo, normalized_title]``
    tuples (per-layer extractors, see inventory_dedup.py)
  * ``commits``: sorted unique 40-hex git commit SHAs
  * ``rows``/``files``: inventory row/file counts

Also union-level convenience sets across layers (``all_urls``, etc.).

Writes only ``work/dedup_registry.json``.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import inventory_dedup as inv

HEX40_RE = re.compile(r"^[0-9a-f]{40}$")


def collect_commits_record(rec: object) -> set[str]:
    out: set[str] = set()

    def walk(x: object) -> None:
        if isinstance(x, str):
            s = x.strip().lower()
            if HEX40_RE.match(s):
                out.add(s)
        elif isinstance(x, dict):
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)

    walk(rec)
    return out


def build_registry() -> dict:
    registry = {
        "version": "1",
        "layers": {},
    }
    for name in inv.LAYER_ROOTS:
        t = inv.scan_layer(name, inv.LAYER_ROOTS[name], inv.KEY_EXTRACTORS[name])
        commits: set[str] = set()
        for p in inv.iter_files(inv.LAYER_ROOTS[name]):
            for rec in inv.parse_records(p):
                commits.update(collect_commits_record(rec))
        registry["layers"][name] = {
            "urls": sorted(t["urls"]),
            "digests": sorted(t["digests"]),
            "keys": [list(k) for k in sorted(t["keys"])],
            "commits": sorted(commits),
            "rows": t["rows"],
            "files": t["files"],
        }

    union: dict = {
        "urls": set(),
        "digests": set(),
        "keys": set(),
        "commits": set(),
    }
    for layer in registry["layers"].values():
        union["urls"].update(layer["urls"])
        union["digests"].update(layer["digests"])
        union["keys"].update(tuple(k) for k in layer["keys"])
        union["commits"].update(layer["commits"])
    registry["union"] = {
        "urls": sorted(union["urls"]),
        "digests": sorted(union["digests"]),
        "keys": sorted(union["keys"]),
        "commits": sorted(union["commits"]),
    }
    return registry


def main() -> int:
    registry = build_registry()
    out = inv.ROOT / "work" / "dedup_registry.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(registry, indent=2), encoding="utf-8")
    print(f"wrote {out}")
    for name, layer in registry["layers"].items():
        print(
            f"  {name}: urls={len(layer['urls'])} digests={len(layer['digests'])} "
            f"keys={len(layer['keys'])} commits={len(layer['commits'])} rows={layer['rows']}"
        )
    u = registry["union"]
    print(
        f"  union: urls={len(u['urls'])} digests={len(u['digests'])} "
        f"keys={len(u['keys'])} commits={len(u['commits'])}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
