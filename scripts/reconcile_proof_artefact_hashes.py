"""Recompute experimental_proof.json artefact hashes from the committed bytes.

The artefacts under experiments_v3/ are the ground truth. result.json
already agrees with them (tests/test_artefact_hashes.py checks that), but
experimental_proof.json -- the upstream source that
scripts/v32_execution.py reads to populate jsonl_v3/findings.jsonl -- still
carries the pre-CRLF-fix hashes. Only the *pointer* is stale: the evidence
itself (stdout.txt showing attacker profit) is unchanged.

Usage:
    python scripts/reconcile_proof_artefact_hashes.py          # rewrite
    python scripts/reconcile_proof_artefact_hashes.py --check  # fail if stale
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PROOF = ROOT / "reports" / "v3" / "experimental_proof.json"

# The record files that inherit the proof's hashes. A record's
# `experiment.artifact_hashes` is a copy of the proof's, so it drifts the
# same way and must be reconciled from the same ground truth.
RECORD_FILES = [
    ROOT / "jsonl_v3" / "findings.jsonl",
    ROOT / "derived_v3" / "records.jsonl",
]


def disk_hashes(base: pathlib.Path, names) -> dict:
    out = {}
    for n in names:
        f = base / n
        if f.is_file():
            out[n] = hashlib.sha256(f.read_bytes()).hexdigest()
    return out


def reconcile_records(strict: bool = True) -> list[str]:
    """Point every record's artefact hashes at the bytes on disk."""
    problems = []
    for path in RECORD_FILES:
        if not path.is_file():
            continue
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip()]
        dirty = False
        for r in rows:
            exp = r.get("experiment") or {}
            d = exp.get("artifact_dir")
            hashes = exp.get("artifact_hashes") or {}
            if not d or not hashes:
                continue
            base = ROOT / d
            truth = disk_hashes(base, hashes.keys())
            for name, want in hashes.items():
                got = truth.get(name)
                if got is None:
                    problems.append(f"{path.name}: {d}/{name} MISSING")
                elif got != want:
                    if strict:
                        problems.append(
                            f"{path.name}: {d}/{name} {want[:12]} != {got[:12]}")
                    else:
                        hashes[name] = got
                        dirty = True
        if dirty:
            path.write_text(
                "".join(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n"
                        for r in rows),
                encoding="utf-8", newline="\n")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    if not PROOF.is_file():
        print(f"missing {PROOF}", file=sys.stderr)
        return 1
    doc = json.loads(PROOF.read_text(encoding="utf-8"))
    stale = []
    changed = 0
    for run in doc.get("runs", []):
        d = run.get("artifact_dir")
        hashes = run.get("artifact_hashes") or {}
        if not d or not hashes:
            continue
        base = ROOT / d
        for name, want in sorted(hashes.items()):
            f = base / name
            if not f.is_file():
                stale.append(f"{d}/{name}: MISSING")
                continue
            got = hashlib.sha256(f.read_bytes()).hexdigest()
            if got != want:
                stale.append(f"{d}/{name}: {want[:12]} != {got[:12]}")
                hashes[name] = got
                changed += 1
    if args.check:
        problems = reconcile_records(strict=True)
        allp = stale + problems
        if allp:
            print(f"{len(allp)} stale artefact hash(es):\n  "
                  + "\n  ".join(allp[:10])
                  + "\n-- run: python scripts/reconcile_proof_artefact_hashes.py",
                  file=sys.stderr)
            return 1
        print("experimental_proof.json artefact hashes are current")
        return 0
    rec_problems = reconcile_records(strict=False)
    if stale:
        PROOF.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n",
                         encoding="utf-8", newline="\n")
        print(f"recomputed {changed} hash(es) across "
              f"{len(doc.get('runs', []))} proof runs -> {PROOF}")
    if rec_problems:
        print(f"reconciled {len(rec_problems)} record-level hash(es) in "
              + ", ".join(p.name for p in RECORD_FILES))
    if not stale and not rec_problems:
        print("nothing stale; no files rewritten")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())