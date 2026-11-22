#!/usr/bin/env python3
"""Profile the VLUN pytest suite: count tests, then time the full run.

Stdlib only. Two phases:

1. ``python -m pytest -q --durations=40 --collect-only`` (fast) -> test count.
2. ``python -m pytest -q --durations=40`` -> full run whose output is tee'd to
   ``reports/_pytest_profile.txt``. The 40 slowest tests (cumulative duration)
   and the total elapsed time appear at the tail of that file.

Usage:
    python scripts/profile_pytest.py            # both phases
    python scripts/profile_pytest.py --count    # phase 1 only
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORT = ROOT / "reports" / "_pytest_profile.txt"
PY = sys.executable


def run(args: list[str], timeout: int | None = None) -> tuple[int, str, float]:
    """Run a pytest invocation, return (returncode, combined output, seconds)."""
    t0 = time.monotonic()
    try:
        proc = subprocess.run(
            [PY, "-m", "pytest", *args],
            cwd=str(ROOT), capture_output=True, text=True,
            errors="replace", timeout=timeout,
        )
        rc, out = proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except subprocess.TimeoutExpired as exc:
        rc = 124
        out = (exc.stdout or b"").decode("utf-8", "replace") if isinstance(
            exc.stdout, bytes) else (exc.stdout or "")
        out += (exc.stderr or b"").decode("utf-8", "replace") if isinstance(
            exc.stderr, bytes) else (exc.stderr or "")
        out += f"\nPROFILE TIMEOUT after {timeout}s\n"
    return rc, out, time.monotonic() - t0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", action="store_true",
                    help="only run the fast collect-only phase")
    ap.add_argument("--timeout", type=int, default=3600,
                    help="seconds allowed for the full run (default 3600)")
    args = ap.parse_args()

    rc, out, secs = run(["-q", "--durations=40", "--collect-only"])
    tail = [ln for ln in out.splitlines() if "collected" in ln or "error" in ln.lower()]
    print(f"[phase 1] collect-only: rc={rc} elapsed={secs:.1f}s")
    for ln in tail[-5:]:
        print("  " + ln)
    if args.count:
        return rc

    print(f"[phase 2] full suite (timeout={args.timeout}s) ...", flush=True)
    rc, out, secs = run(["-q", "--durations=40"], timeout=args.timeout)
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    header = (f"pytest profile\ncommand: {PY} -m pytest -q --durations=40\n"
              f"returncode: {rc}\nwall_seconds: {secs:.1f}\n\n")
    REPORT.write_text(header + out, encoding="utf-8", newline="\n")
    print(f"[phase 2] rc={rc} elapsed={secs:.1f}s -> {REPORT}")
    # Echo just the durations block + summary; full output is in the report.
    lines = out.splitlines()
    start = next((i for i, ln in enumerate(lines)
                  if "slowest" in ln.lower() and "durations" in ln.lower()), None)
    for ln in (lines[start:] if start is not None else lines[-45:]):
        print("  " + ln)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
