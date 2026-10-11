#!/usr/bin/env python3
"""Validate the multi-language source layer.

    python scripts/check_ml_layer.py            # every check, exit 1 on failure
    python scripts/check_ml_layer.py --stats    # also print counts per language/tier

The Solidity half of the dataset is gated by scripts/validate.py. This is the
same job for jsonl_ml/: schema shape, closed vocabularies, unique ids, every
finding pointing at a source that actually exists in the registry, and no field
claiming experimental verification without an experiment behind it.
"""

from __future__ import annotations

import argparse
import collections
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vlun import DATASET_VERSION, SCHEMA_VERSION, log  # noqa: E402
from vlun_ml import (  # noqa: E402
    ML_JSONL, check_layer,
    load_findings, load_sources,
)


def stats() -> None:
    srcs, finds = load_sources(), load_findings()
    log(f"sources: {len(srcs)}  findings: {len(finds)}")
    log("  by language: " + str(dict(collections.Counter(f.get('language') for f in finds))))
    log("  by tier:     " + str(dict(collections.Counter(s.get('source_tier') for s in srcs))))
    log("  by origin:   " + str(dict(collections.Counter(s.get('evidence_origin') for s in srcs))))
    log("  by verification: "
        + str(dict(collections.Counter((s.get('verification') or {}).get('status') for s in srcs))))
    log("  ecosystems:  " + str(dict(collections.Counter(s.get('ecosystem') for s in srcs))))
    ev = collections.Counter()
    for f in finds:
        for v in (f.get("evidence") or {}).values():
            if isinstance(v, dict) and v.get("evidence_type"):
                ev[v["evidence_type"]] += 1
    log("  evidence types: " + str(dict(ev)))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--stats", action="store_true")
    ap.add_argument("--quiet", action="store_true",
                    help="suppress per-record output (for run_gates.py)")
    args = ap.parse_args()

    log(f"ml layer check  dataset={DATASET_VERSION} schema={SCHEMA_VERSION}")
    if not ML_JSONL.exists():
        log(f"SKIPPED: {ML_JSONL.name}/ does not exist - no multi-language records to check")
        return 2

    total, errors = check_layer()
    if args.stats and not args.quiet:
        stats()
    if errors:
        if not args.quiet:
            for e in errors[:80]:
                log(f"  [FAIL] {e}")
            if len(errors) > 80:
                log(f"  ... {len(errors) - 80} more")
        log(f"{len(errors)} failure(s) across {total} records")
        return 1
    if total == 0:
        # Fail closed: an empty layer must never report "ok: 0 records".
        # A missing jsonl_ml/ returns 2 (SKIPPED) above; an existing-but-
        # empty layer is a broken ingest, not a pass.
        log("FAIL: ml layer present but 0 records checked (empty ingest)")
        return 1
    log(f"ok: {total} records, 0 failures")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
