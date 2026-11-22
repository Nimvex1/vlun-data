"""propagate_hydration.py -- carry verbatim inline fields into derived tables.

Run AFTER the adapters have regenerated 04_admitted/ and benchmark_wave1/ from
the hydrated 03_candidates/ files.  For every derived row this script

  1. resolves the row back to a hydrated candidate (by candidate_id, with a
     deterministic longest-substring fallback for pair/axis task ids),
  2. copies the candidate's additive inline fields onto the row, and
  3. DROPS the row when no hydrated candidate can be resolved -- so every row
     that remains in the admitted/benchmark tables is FULLY_TRAINABLE.

Stdlib only. Writes only inside wave1/.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _common import WAVE1, guard_wave1, read_jsonl, utc_now, write_json, write_jsonl
from hydration_lib import ALLOWED_INLINE_FIELDS, fully_trainable

CAND_DIR = WAVE1 / "03_candidates"
ADMITTED = WAVE1 / "04_admitted"
BENCH = WAVE1 / "benchmark_wave1"
REPORT = WAVE1 / "reports_wave1" / "propagate_hydration.json"


def build_index() -> dict[str, dict]:
    idx: dict[str, dict] = {}
    for p in sorted(CAND_DIR.rglob("*.jsonl")):
        for row in read_jsonl(p):
            if not fully_trainable(row):
                continue
            cid = str(row.get("candidate_id") or "")
            if cid:
                idx[cid] = row
    return idx


def resolve(row: dict, idx: dict[str, dict]) -> dict | None:
    cid = str(row.get("candidate_id") or "")
    if cid in idx:
        return idx[cid]
    # axis/pair/invariant task ids embed a candidate id (or two) as substrings.
    hits = [k for k in idx if k and k in cid]
    if hits:
        return idx[max(hits, key=len)]
    # family-derived ids: try the finding id carried under `source`
    src = row.get("source") or {}
    if isinstance(src, dict):
        fid = str(src.get("finding_id") or "")
        if fid in idx:
            return idx[fid]
        hits = [k for k in idx if k and k in fid]
        if hits:
            return idx[max(hits, key=len)]
    return None


def attach(row: dict, cand: dict) -> dict:
    out = dict(row)
    for key in ALLOWED_INLINE_FIELDS:
        if key in cand and key not in out:
            out[key] = cand[key]
    out["hydration_resolved_from"] = str(cand.get("candidate_id") or "")[:200]
    return out


def main() -> None:
    idx = build_index()
    summary: dict[str, dict] = {}
    targets: list[tuple[str, Path]] = []
    for p in sorted(ADMITTED.rglob("*.jsonl")):
        targets.append(("admitted/" + str(p.relative_to(ADMITTED)), p))
    for p in sorted(BENCH.glob("*.jsonl")):
        targets.append(("benchmark_wave1/" + p.name, p))

    for label, path in targets:
        rows = list(read_jsonl(guard_wave1(path)))
        kept, dropped = [], 0
        for row in rows:
            cand = resolve(row, idx)
            if cand is not None:
                out = attach(row, cand)
                if fully_trainable(out):
                    kept.append(out)
                    continue
            dropped += 1
        write_jsonl(guard_wave1(path), kept)
        summary[label] = {"before": len(rows), "kept": len(kept), "dropped": dropped}
        print(f"[propagate] {label}: before={len(rows)} kept={len(kept)} dropped={dropped}")

    payload = {
        "generated_at": utc_now(),
        "candidate_index_size": len(idx),
        "tables": summary,
        "totals": {
            "before": sum(s["before"] for s in summary.values()),
            "kept": sum(s["kept"] for s in summary.values()),
            "dropped": sum(s["dropped"] for s in summary.values()),
        },
    }
    write_json(guard_wave1(REPORT), payload)
    print(f"[propagate] totals before={payload['totals']['before']} "
          f"kept={payload['totals']['kept']} dropped={payload['totals']['dropped']}")


if __name__ == "__main__":
    main()
