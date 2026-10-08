#!/usr/bin/env python3
"""Build the committed SHA index for the v3.1 no-invention gate.

The v3.1 gate must verify that every commit SHA asserted in an admitted
normalization fragment genuinely occurs in its parent source document.
The sources live in V3/clones (git-ignored, must never be redistributed),
so the gate cannot re-read them on a fresh clone. This builder runs on a
machine WITH the clones and records, per source file (keyed by file
sha256), the sorted set of 40-hex SHAs its extracted text contains --
hashes only, no third-party prose. The gate checks fragments against
this committed index; a missing file entry fails closed with the regen
command below.

Writes derived_v3/source_sha_index.json. Exit 1 if any referenced
source file is absent (the index cannot be built honestly without it).

    python scripts/build_source_sha_index.py
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import v31_extract as X  # noqa: E402
import vlun_v3 as V  # noqa: E402
from vlun import read_jsonl, write_json  # noqa: E402

SHA40 = re.compile(r"[0-9a-f]{40}")
OUT = V.DERIVED_V3 / "source_sha_index.json"


def main() -> int:
    frags = read_jsonl(V.DERIVED_V3 / "normalization_fragments.jsonl")
    ledger_by_id = {c["candidate_id"]: c
                    for c in read_jsonl(V.DERIVED_V3 / "candidate_ledger.jsonl")}
    # Same population the gate checks: admitted fragments asserting at
    # least one full-length SHA.
    parents: dict[str, dict] = {}
    for f in frags:
        if f.get("fragment_status") != "admitted":
            continue
        if not any(SHA40.match(s.get("sha", ""))
                   for s in f.get("commit_shas", [])):
            continue
        pid = f.get("parent_candidate_id", "")
        if pid not in parents:
            parents[pid] = ledger_by_id.get(pid)
    missing = sorted(pid for pid, p in parents.items() if p is None)
    if missing:
        print(f"build_source_sha_index: {len(missing)} parent(s) not in "
              f"candidate_ledger.jsonl: {missing[:5]}")
        return 1
    files: dict[str, dict] = {}
    absent = []
    for pid, parent in sorted(parents.items()):
        loc = parent.get("source_location", "")
        path = X.resolve_path(loc)
        if path is None:
            absent.append(f"{pid} <- {loc}")
            continue
        digest = V.sha256_file(path)
        if digest not in files:
            text, _quality = X.get_text(parent)
            files[digest] = {
                "source_location": loc,
                "shas": sorted(set(SHA40.findall(text))),
            }
    if absent:
        print(f"build_source_sha_index: {len(absent)} source file(s) absent "
              f"from V3/clones (fetch_sources.py first):")
        for a in absent[:10]:
            print(f"  - {a}")
        return 1
    write_json(OUT, {"generated_by": "scripts/build_source_sha_index.py",
                     "files": files})
    n_sha = sum(len(v["shas"]) for v in files.values())
    print(f"build_source_sha_index: {len(files)} source file(s), "
          f"{n_sha} SHA(s) -> {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
