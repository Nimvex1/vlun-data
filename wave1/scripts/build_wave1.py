"""build_wave1.py — deterministic Wave-1 build orchestrator.

Runs every adapter in order, then the judge-family split rebalance. Stdlib only.
Writes only inside wave1/. Verification is intentionally separate: run
dedup_check.py --check, validate_wave1.py and unittest afterwards.
"""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

from _common import WAVE1, guard_wave1, utc_now, write_json

SCRIPTS = WAVE1 / "scripts"
ORDER = [
    "adapters/mitigation.py",
    "adapters/formal.py",
    "adapters/markdown.py",
    "adapters/ghsa.py",
    "adapters/judge.py",
    "adapters/reevmbench.py",
    "rebalance_splits.py",
]


def main() -> None:
    started = time.time()
    ran = []
    failures = []
    for rel in ORDER:
        script = SCRIPTS / rel
        if not script.exists():
            failures.append({"script": rel, "error": "missing"})
            print(f"[build_wave1] MISSING {rel}")
            continue
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

    report = {
        "built_at": utc_now(),
        "seconds": round(time.time() - started, 2),
        "order": ORDER,
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
