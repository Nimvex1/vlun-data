"""dedup_check.py — verify zero admitted keys collide with the canonical registry.

Usage: python wave1/scripts/dedup_check.py [--check]

Reads every file under wave1/04_admitted/**/*.jsonl. Each admitted row must
carry a non-empty `dedup_keys` list. A key present in 01_dedup/registry.jsonl
is a collision. With --check, exit code 1 if any collision exists.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from _common import (
    WAVE1,
    guard_wave1,
    load_registry,
    read_jsonl,
    write_json,
)

ADMITTED = WAVE1 / "04_admitted"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="exit 1 on any collision")
    ap.add_argument("--no-write", action="store_true",
                    help="do not refresh reports_wave1/dedup_check.json (for gate runs)")
    args = ap.parse_args()

    registry = load_registry()
    collisions: list[dict] = []
    admitted_rows = 0
    keys_checked = 0
    per_source: dict[str, int] = {}

    if ADMITTED.exists():
        for p in sorted(ADMITTED.rglob("*.jsonl")):
            src = p.relative_to(ADMITTED).parts[0] if p.relative_to(ADMITTED).parts else "unknown"
            for row in read_jsonl(p):
                admitted_rows += 1
                per_source[src] = per_source.get(src, 0) + 1
                keys = row.get("dedup_keys") or []
                if not keys:
                    collisions.append(
                        {
                            "source": src,
                            "candidate_id": row.get("candidate_id"),
                            "key": "<MISSING_DEDUP_KEYS>",
                            "reason": "admitted row has no dedup_keys",
                        }
                    )
                    continue
                for k in keys:
                    keys_checked += 1
                    if k in registry:
                        r = registry[k]
                        collisions.append(
                            {
                                "source": src,
                                "candidate_id": row.get("candidate_id"),
                                "key": k,
                                "collides_with_layer": r.get("layer"),
                                "collides_with_value": r.get("value"),
                            }
                        )

    manifest_count = 0
    mpath = WAVE1 / "01_dedup" / "overlap_manifest.jsonl"
    if mpath.exists():
        manifest_count = sum(1 for _ in read_jsonl(mpath))

    # No run wall-clock field: this report is committed and byte-hashed by the
    # JSON catalog, so a fresh utc_now() on every run would make it stale.
    # All functional content (counts, collisions, verdict) is deterministic.
    report = {
        "registry_size": len(registry),
        "admitted_rows": admitted_rows,
        "dedup_keys_checked": keys_checked,
        "admitted_by_source": per_source,
        "collisions": len(collisions),
        "collision_details": collisions[:100],
        "overlap_manifest_rows": manifest_count,
        "verdict": "PASS" if not collisions else "FAIL",
    }
    if not args.no_write:
        write_json(guard_wave1(WAVE1 / "reports_wave1" / "dedup_check.json"), report)
    print(f"[dedup_check] registry={len(registry)} admitted={admitted_rows} keys={keys_checked} "
          f"collisions={len(collisions)} overlaps={manifest_count} -> {report['verdict']}")
    for c in collisions[:10]:
        print("  COLLISION", c)
    if args.check and collisions:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
