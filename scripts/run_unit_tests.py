#!/usr/bin/env python3
"""Run the stdlib unit suite within the gate's time budget.

Most tests are independent and run under pytest-xdist. Three modules act on
the shared repository root (rebuild-parity snapshots and the catalog probe),
so they must run serially in a second step; running them in parallel makes
other workers observe temporarily removed or newly created files.

Exit 0 only when both steps pass.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable
SERIAL_MODULES = (
    "tests/test_reproducibility_parity.py",
    "tests/test_derived_parity.py",
    "tests/test_json_catalog.py",
)
IGNORES = [arg for module in SERIAL_MODULES for arg in ("--ignore", module)]
# Leftovers from an interrupted parallel run would make the serial probe fail.
for stale in ("work/.repro_replay.lock", "reports/untracked_stray_probe.json"):
    (ROOT / stale).unlink(missing_ok=True)

STEPS = [
    [PY, "-m", "pytest", "-q", "-n", "4", *IGNORES],
    [PY, "-m", "pytest", "-q", *SERIAL_MODULES],
]


def main() -> int:
    for cmd in STEPS:
        print("run_unit_tests.py:", " ".join(cmd[1:]), flush=True)
        proc = subprocess.run(cmd, cwd=str(ROOT))
        if proc.returncode != 0:
            return proc.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
