#!/usr/bin/env python3
"""Static-analysis cross-check.

Slither's output is a *signal*, never ground truth. This script runs it where the
repository actually builds, stores the raw JSON, and then reports how the signal
lines up with the dataset's own findings and with the executed experiments.

Three outcomes are distinguished, and only the third is reported as a clean bill
of health — which it never is:

    available     slither analysed the sources and produced detectors
    partial       slither ran but the compile step was incomplete, so the detector
                  set is not trustworthy; the report says so
    unavailable   the repository could not be analysed here at all

A repository that does not build is never reported as "no issues found".

    python scripts/run_static_analysis.py
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from redact_machine_paths import redact_obj  # noqa: E402  (one redaction convention, repo-wide)
from vlun import REPORTS, WORK, log, write_json  # noqa: E402

WT = WORK / "wt"
SLITHER_DIR = WORK / "slither"

# Only repositories that build with the recorded toolchain settings.
TARGETS = [
    {"key": "renft-vulnerable", "path": WT / "renft-smart", "commit": "3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291",
     "env": {}, "build_env": {}},
    {"key": "wildcat", "path": WORK / "repos" / "code-423n4__2024-08-wildcat",
     "commit": "7c5d8389b2a368ce6c4fc79e50c39eac3516ea5e",
     "env": {"FOUNDRY_DYNAMIC_TEST_LINKING": "false"}, "build_env": {}},
    {"key": "gte-perps", "path": WORK / "repos" / "code-423n4__2025-08-gte-perps",
     "commit": "4e38f46e1d0479762b9b786de4d2ba26bb98b55e", "env": {}, "build_env": {}},
    {"key": "panoptic", "path": WORK / "repos" / "code-423n4__2025-06-panoptic",
     "commit": "eea2c931b1cbce1da01586e42ba298814de40d31", "env": {}, "build_env": {}},
    {"key": "decent", "path": WORK / "repos" / "code-423n4__2024-01-decent",
     "commit": "5d1962143ee566e7f9354b735bff3492b8f82761", "env": {}, "build_env": {}},
    {"key": "noya", "path": WORK / "repos" / "code-423n4__2024-04-noya",
     "commit": "7e7b0ffb53b516b95c7900d25fb00af8f108727f",
     "env": {}, "build_env": {"FOUNDRY_OPTIMIZER": "true", "FOUNDRY_OPTIMIZER_RUNS": "1000000"}},
]

# Detector families that speak to a specific dataset claim rather than to style.
RELEVANT = {
    "reentrancy-eth": "reentrancy",
    "reentrancy-no-eth": "reentrancy",
    "reentrancy-benign": "reentrancy",
    "reentrancy-events": "reentrancy",
    "reentrancy-unlimited-gas": "reentrancy",
    "arbitrary-send-eth": "arbitrary_value_transfer",
    "arbitrary-send-erc20": "arbitrary_value_transfer",
    "unchecked-transfer": "arbitrary_value_transfer",
    "suicidal": "selfdestruct",
    "controlled-delegatecall": "delegatecall",
    "delegatecall-loop": "delegatecall",
    "tx-origin": "tx_origin",
    "unchecked-lowlevel": "low_level_call",
    "calls-loop": "low_level_call",
    "shadowing-constructor": "state_variable_shadowing",
    "incorrect-exp": "arithmetic",
    "divide-before-multiply": "arithmetic",
}


def version() -> str:
    try:
        r = subprocess.run(["slither", "--version"], capture_output=True, text=True, timeout=120)
        m = r.stdout.strip().split()
        return m[0] if m else "unknown"
    except Exception:  # noqa: BLE001
        return "unavailable"


def analyse(target: dict, timeout: int = 3000) -> dict:
    path = Path(target["path"])
    out_json = SLITHER_DIR / f"{target['key']}.json"
    out_json.parent.mkdir(parents=True, exist_ok=True)
    record = {"repository": target["key"], "commit": target["commit"],
              "command": f"slither . --json {out_json.name}", "path": str(path)}
    if not (path / ".git").exists():
        record.update(static_analysis_status="unavailable",
                      reason="the repository is not present locally")
        return record

    env = dict(os.environ)
    env.update(target.get("env") or {})
    env.update(target.get("build_env") or {})
    # Slither's forge backend shells out to forge; it inherits the same settings.
    t0 = time.time()
    cmd = ["slither", ".", "--json", str(out_json)]
    try:
        r = subprocess.run(cmd, cwd=str(path), capture_output=True, text=True,
                           timeout=timeout, env=env, errors="replace")
        seconds = round(time.time() - t0, 1)
    except subprocess.TimeoutExpired:
        record.update(static_analysis_status="unavailable",
                      reason=f"slither exceeded {timeout}s", seconds=timeout)
        return record

    record["seconds"] = seconds
    record["exit_code"] = r.returncode
    record["stderr_tail"] = (r.stderr or "")[-1500:]
    if not out_json.exists():
        record.update(static_analysis_status="unavailable",
                      reason="slither produced no JSON output")
        return record
    try:
        doc = json.loads(out_json.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        record.update(static_analysis_status="unavailable",
                      reason=f"slither output was not valid JSON: {exc}")
        return record

    det = doc.get("results", {}).get("detectors", []) or []
    record["static_analysis_status"] = "available" if doc.get("success") else "partial"
    record["detectors_fired"] = len(det)
    record["by_impact"] = {}
    families: dict[str, int] = {}
    for x in det:
        record["by_impact"][x.get("impact", "?")] = record["by_impact"].get(
            x.get("impact", "?"), 0) + 1
        base = x.get("check", "")
        if base in RELEVANT:
            families[RELEVANT[base]] = families.get(RELEVANT[base], 0) + 1
    record["by_security_family"] = families
    record["detector_names"] = sorted({x.get("check") for x in det})[:80]
    record["raw_json"] = str(out_json.relative_to(REPORTS.parent)).replace("\\", "/")
    record["raw_json_sha256"] = _sha(out_json)
    if not doc.get("success"):
        record["reason"] = ("slither reported failure; the compile step was incomplete so "
                            "the absence of a detector is NOT evidence of absence")
    return record


def _sha(p: Path) -> str:
    import hashlib
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--only", help="run a single repository key")
    ap.add_argument("--timeout", type=int, default=3000)
    args = ap.parse_args()

    targets = [t for t in TARGETS if not args.only or t["key"] == args.only]
    records = []
    for t in targets:
        log(f"  slither {t['key']} ...")
        rec = analyse(t, args.timeout)
        records.append(rec)
        log(f"    {rec['static_analysis_status']}: "
            f"{rec.get('detectors_fired', 0)} detectors")

    from collections import Counter
    doc = {
        "generated_by": "scripts/run_static_analysis.py",
        "tool": "slither",
        "tool_version": version(),
        "policy": ("Slither output is an independent signal, not ground truth. A repository "
                   "that could not be analysed is reported `unavailable`; it is never "
                   "reported as clean."),
        "limitations": [
            "detector coverage depends on the project compiling; partial compiles produce "
            "partial coverage",
            "Slither models neither the deployment nor the off-chain protocol roles, so a "
            "clean run says nothing about access control in practice",
            "findings are reported at the analysed commit, which is the audited revision, "
            "not today's branch tip",
        ],
        "by_status": dict(Counter(r["static_analysis_status"] for r in records)),
        "repositories": records,
    }
    write_json(REPORTS / "static_analysis.json", redact_obj(doc))
    log(f"static_analysis.json: {doc['by_status']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())