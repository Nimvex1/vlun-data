"""build_wave1.py — deterministic Wave-1 build orchestrator.

Order matters:
  1. adapters regenerate 03_candidates/, 04_admitted/ and benchmark_wave1/;
  2. hydrate_wave1.py hydrates the freshly regenerated candidate rows from
     verbatim local/cache sources and quarantines the unhydratable ones;
  3. propagate_hydration.py re-attaches the inline fields to the derived tables
     and DROPS any row that cannot resolve to a hydrated candidate;
  4. rebalance_splits.py / assign_group_splits.py restore group-disjoint splits.

Stdlib only. Writes only inside wave1/ (the hydrator is the one authorised
exception: it writes the wave1/ tree from scripts/hydrate_wave1.py).
Verification is separate: run dedup_check.py --check, validate_wave1.py and
the wave1 unittest suite afterwards.
"""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

from _common import WAVE1, ROOT, guard_wave1, utc_now, write_json

SCRIPTS = WAVE1 / "scripts"
ORDER = [
    "adapters/mitigation.py",
    "adapters/formal.py",
    "adapters/markdown.py",
    "adapters/ghsa.py",
    "adapters/judge.py",
    "adapters/reevmbench.py",
]
POST = [
    ROOT / "scripts" / "hydrate_wave1.py",
    SCRIPTS / "propagate_hydration.py",
    SCRIPTS / "rebalance_splits.py",
]


def _run(script: Path, ran: list[str], failures: list[dict]) -> None:
    rel = str(script.relative_to(ROOT))
    if not script.exists():
        failures.append({"script": rel, "error": "missing"})
        print(f"[build_wave1] MISSING {rel}")
        return
    print(f"[build_wave1] running {rel}")
    proc = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, timeout=900)
    tail = (proc.stdout or "").strip().splitlines()[-3:]
    for line in tail:
        print("   " + line)
    if proc.returncode != 0:
        failures.append({"script": rel, "returncode": proc.returncode,
                         "stderr": (proc.stderr or "")[-1000:]})
        print(f"[build_wave1] FAILED {rel}: {(proc.stderr or '')[-300:]}")
    ran.append(rel)


def main() -> None:
    started = time.time()
    ran: list[str] = []
    failures: list[dict] = []
    for rel in ORDER:
        _run(SCRIPTS / rel, ran, failures)
    for script in POST:
        _run(script, ran, failures)

    report = {
        "built_at": utc_now(),
        "seconds": round(time.time() - started, 2),
        "order": ORDER + [str(s.relative_to(ROOT)) for s in POST],
        "ran": ran,
        "failures": failures,
        "verdict": "PASS" if not failures else "FAIL",
    }
    write_json(guard_wave1(WAVE1 / "reports_wave1" / "build_wave1.json"), report)
    print(f"[build_wave1] verdict={report['verdict']} in {report['seconds']}s; "
          f"ran={len(ran)} failures={len(failures)}")
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
