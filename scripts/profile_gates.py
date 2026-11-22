#!/usr/bin/env python3
"""Wall-clock profiler for the default gate selection in run_gates.py.

Runs the SAME 54 gates a plain `python scripts/run_gates.py` would run, one at
a time, with a 120-second per-gate timeout.  Any gate over 15 seconds is
flagged.  TIMEOUTs are recorded and the run continues.  A full log, with a
descending per-gate elapsed table at the end, is written to
reports/_gate_profile.txt.

    python scripts/profile_gates.py
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

# Import the canonical gate list and selection so this profiler can never
# drift from run_gates.py.  Importing is side-effect free: main() only runs
# under __main__.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_gates as rg  # noqa: E402

ROOT = rg.ROOT
LOG = ROOT / "reports" / "_gate_profile.txt"


def default_gates():
    """Reproduce run_gates.main()'s default (no --only) selection exactly."""
    want = set(rg.ONLY_MAP)  # full run: every group key
    names: set[str] = set()
    for k in want:
        names.update(rg.ONLY_MAP.get(k, [k]))
    return [(name, cmd) for name, cmd in rg.GATES if name in names]


def main() -> int:
    gates = default_gates()
    n = len(gates)
    LOG.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []

    def emit(msg: str) -> None:
        print(msg, flush=True)
        lines.append(msg)

    profile_start = time.perf_counter()
    emit(f"gate profile: {n} gates, 120s timeout each, 15s slow threshold")
    results: list[tuple[str, float, str]] = []  # (name, elapsed, status)

    for i, (name, cmd) in enumerate(gates, 1):
        emit(f"[ {i} / {n} ] {name} ...")
        t0 = time.perf_counter()
        status = "OK"
        elapsed = 0.0
        try:
            p = subprocess.run(cmd, cwd=str(ROOT), capture_output=True,
                               text=True, timeout=120, errors="replace")
            elapsed = time.perf_counter() - t0
            rc = p.returncode
            status = f"rc={rc}"
        except subprocess.TimeoutExpired:
            elapsed = time.perf_counter() - t0
            status = "TIMEOUT"
        except OSError as exc:
            elapsed = time.perf_counter() - t0
            status = f"ERROR({exc})"

        slow = "  *** SLOW ***" if elapsed > 15 else ""
        emit(f"    -> {status}  {elapsed:.2f}s{slow}")
        results.append((name, elapsed, status))

    total = time.perf_counter() - profile_start
    emit("")
    emit(f"TOTAL PROFILE RUNTIME: {total:.2f}s ({total / 60:.1f} min)")
    emit("")
    emit("=== PER-GATE ELAPSED (descending) ===")
    for rank, (name, elapsed, status) in enumerate(
            sorted(results, key=lambda r: -r[1]), 1):
        flag = "  *** SLOW ***" if elapsed > 15 else ""
        emit(f"{rank:2d}. {elapsed:8.2f}s  {status:10s}  {name}{flag}")

    timeouts = [name for name, _, status in results if status == "TIMEOUT"]
    emit("")
    emit("=== TIMEOUT GATES ===")
    emit(", ".join(timeouts) if timeouts else "(none)")

    LOG.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"full log: {LOG}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
