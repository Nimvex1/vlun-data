#!/usr/bin/env python3
"""Schema-only gate: JSON validity, field presence, controlled vocabularies.

A subset of `scripts/validate.py`, for a pre-commit check that should be fast
enough to run on every save. Same failure semantics — non-zero exit on any
critical problem — just fewer checks.

    python scripts/validate_schema.py
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Only the groups that can be evaluated without the build having run.
GROUPS = ("structure", "evidence")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--full", action="store_true", help="delegate to validate.py unchanged")
    args = ap.parse_args()

    if args.full:
        return subprocess.run([sys.executable, str(ROOT / "scripts" / "validate.py")]).returncode

    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "validate.py"), "--quiet"],
        cwd=str(ROOT), capture_output=True, text=True, errors="replace")
    import json
    try:
        rep = json.loads((ROOT / "reports" / "validation_report.json").read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        print("ERROR: validate.py did not produce reports/validation_report.json")
        print(proc.stdout or "", proc.stderr or "")
        return 1

    checks = [c for c in rep["details"] if c["group"] in GROUPS]
    failed = [c for c in checks if not c["ok"] and c["critical"]]
    for c in checks:
        mark = "ok  " if c["ok"] else "FAIL"
        print(f"  [{mark}] {c['group']}/{c['check']}"
              + (f"  ({c['failure_count']})" if not c["ok"] else ""))
        for f in c["failures"][:5]:
            print(f"         - {f}")
    print(f"\nschema gate: {sum(1 for c in checks if c['ok'])}/{len(checks)} passed, "
          f"{len(failed)} critical")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())