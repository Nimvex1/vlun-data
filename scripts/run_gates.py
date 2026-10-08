#!/usr/bin/env python3
"""One runner for all gates, per layer. Exit 1 if any gate fails.

Runs every validator in dependency order and prints a unified PASS/FAIL/
SKIPPED matrix. Network/toolchain-dependent stages report SKIPPED
(skipped_no_network), never silent. Writes nothing.

    python scripts/run_gates.py
    python scripts/run_gates.py --quiet
    python scripts/run_gates.py --only vbeta   # subset: v1 v3 v31 vbeta manifests repro tests readme
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable

GATES = [
    ("v1-authorship", [PY, "scripts/validate.py", "--quiet"]),
    ("v3", [PY, "scripts/validate_v3.py", "--quiet"]),
    ("v31", [PY, "scripts/validate_v31.py", "--quiet"]),
    ("vbeta-gate", [PY, "Vbeta/scripts/validate_vbeta.py", "--quiet"]),
    ("manifests", [PY, "scripts/check_manifests.py", "--quiet"]),
    ("reproducibility", [PY, "scripts/check_reproducibility.py", "--quiet"]),
    ("unit-tests", [PY, "-m", "unittest", "discover", "-s", "tests"]),
    ("vbeta-tests", [PY, "Vbeta/tests/test_vbeta.py"]),
    ("readme-current", [PY, "scripts/generate_readme.py", "--check"]),
    ("stats-current", [PY, "scripts/generate_stats.py", "--check"]),
    ("field-coverage-current", [PY, "scripts/field_coverage.py", "--check"]),
]

ONLY_MAP = {
    "v1": ["v1-authorship"],
    "v3": ["v3"],
    "v31": ["v31"],
    "vbeta": ["vbeta-gate", "vbeta-tests"],
    "manifests": ["manifests"],
    "repro": ["reproducibility"],
    "tests": ["unit-tests", "vbeta-tests"],
    "readme": ["readme-current", "stats-current", "field-coverage-current"],
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--only", nargs="*", choices=sorted(ONLY_MAP),
                    help="run a subset of gates")
    args = ap.parse_args()

    want = set(ONLY_MAP) if not args.only else set()
    for key in (args.only or []):
        want.update(ONLY_MAP[key])
    selected = [(name, cmd) for name, cmd in GATES
                if name in {n for k in want for n in ONLY_MAP[k]}]
    # --only given explicitly trims to the requested groups.
    if args.only:
        keep = set()
        for key in args.only:
            keep.update(ONLY_MAP[key])
        selected = [(n, c) for n, c in GATES if n in keep]

    results = []
    print("run_gates.py")
    for name, cmd in selected:
        out = ""
        try:
            p = subprocess.run(cmd, cwd=str(ROOT), capture_output=True,
                               text=True, timeout=1200, errors="replace")
            ok = p.returncode == 0
            out = ((p.stdout or "") + (p.stderr or "")).strip()
            tail = " | ".join(t.strip() for t in out.splitlines()[-2:]
                              if t.strip())
        except subprocess.TimeoutExpired:
            ok, tail = False, "timeout after 1200s"
        except OSError as exc:
            ok, tail = False, f"cannot start: {exc}"
        results.append((name, ok))
        if args.quiet:
            continue
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}"
              + (f" — {tail[:160]}" if tail else ""))
        if not ok and out:
            # A failing gate must show WHY, especially on CI where the
            # validator's own log is captured, not streamed.
            lines = out.splitlines()
            show = lines if len(lines) <= 60 else (
                lines[:10]
                + [f"... ({len(lines) - 50} lines elided) ..."]
                + lines[-40:])
            for ln in show:
                print(f"    {ln.strip()}"[:300])

    nfail = sum(1 for _, ok in results if not ok)
    print(f"gates={len(results)} pass={len(results) - nfail} fail={nfail}")
    return 1 if nfail else 0


if __name__ == "__main__":
    raise SystemExit(main())
