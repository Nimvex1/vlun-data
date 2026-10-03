#!/usr/bin/env python3
"""Fuse PoC classification with experiment outcomes.

Reads:
    jsonl/exploits.jsonl                 the original evidence layer
    reports/verified_experiments.json    what was actually run, by scripts/run_verified_experiments.py
    reports/verification_stats.json      the v2 attempt log, kept for comparison

Writes:
    reports/reproduction_stats.json      class distribution, L-level distribution, failure taxonomy
    reports/reproduction_manifest.json   per-experiment replay instructions
    experiments/reconstruction_log.jsonl one row per attempted PoC, whatever the outcome

The reconstruction log exists so a reader can tell "the exploit is probably
false" apart from "we could not reproduce it because the historical environment
is unavailable". Those are different claims and only one of them is about the
finding.

Deterministic: same inputs produce the same files.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import poc_classification as pc  # noqa: E402
from vlun import JSONL, REPORTS, ROOT, log, read_jsonl, write_json, write_jsonl  # noqa: E402

EXPERIMENTS_DIR = ROOT / "experiments"


def load_experiments() -> dict[str, dict]:
    f = REPORTS / "verified_experiments.json"
    if not f.exists():
        return {}
    doc = __import__("json").loads(f.read_text(encoding="utf-8"))
    return {e["finding_id"]: e for e in doc.get("experiments", [])}


def load_v2_attempts() -> dict[str, dict]:
    """The v2 attempt log, keyed by finding id, for before/after comparison."""
    f = REPORTS / "verification_stats.json"
    if not f.exists():
        return {}
    import json
    doc = json.loads(f.read_text(encoding="utf-8"))
    out = {}
    for r in doc.get("records", []) or doc.get("per_record", []) or []:
        fid = r.get("finding_id") or r.get("id")
        if fid:
            out[fid] = r
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out-stats", default=str(REPORTS / "reproduction_stats.json"))
    ap.add_argument("--out-log", default=str(EXPERIMENTS_DIR / "reconstruction_log.jsonl"))
    ap.add_argument("--out-manifest", default=str(REPORTS / "reproduction_manifest.json"))
    args = ap.parse_args()

    exploits = read_jsonl(JSONL / "exploits.jsonl")
    experiments = load_experiments()
    v2 = load_v2_attempts()

    classes = Counter()
    levels = Counter()
    per_record = []
    log_rows = []

    for row in exploits:
        fid = row["finding"]["id"]
        ex = row.get("exploit") or {}
        cls = pc.classify(ex)
        base = pc.level_for(cls)
        level, basis = base["level"], base["basis"]

        exp = experiments.get(fid)
        if exp:
            level, basis = pc.upgrade_from_experiment(level, exp)

        classes[cls["poc_class"]] += 1
        levels[level] += 1

        v = (exp or {}).get("revisions", {})
        vuln, fixed = v.get("vulnerable") or {}, v.get("fixed") or {}
        run_reason = (vuln.get("run_failure_reason")
                      or fixed.get("run_failure_reason")
                      or (v2.get(fid) or {}).get("failure_reason"))
        per_record.append({
            "finding_id": fid,
            "repository": row["source"]["repository"],
            "severity": row["finding"].get("severity"),
            "validation_status": row["finding"].get("validation_status"),
            "poc_class": cls["poc_class"],
            "poc_class_rationale": cls["rationale"],
            "poc_class_signals": cls["signals"],
            "poc_level": level,
            "poc_level_basis": basis,
            "poc_level_evidence": ("experimentally_verified" if exp
                                    else "reported_claim"),
            "experiment": {
                "attempted": bool(exp),
                "verdict": (exp or {}).get("verdict"),
                "vulnerable_revision": vuln.get("commit"),
                "vulnerable_status": vuln.get("status"),
                "fixed_revision": fixed.get("commit"),
                "fixed_status": fixed.get("status"),
                "observed_failure": vuln.get("observed_failure"),
                "run_failure_reason": run_reason,
                "run_failure_detail": vuln.get("run_failure_detail"),
                "inconclusive_reason": (exp or {}).get("inconclusive_reason"),
            },
        })

        log_rows.append({
            "attempt_id": f"attempt::{fid}",
            "finding_id": fid,
            "source_poc_type": cls["poc_class"],
            "original_poc_available": bool(ex.get("available")),
            "reconstruction_attempted": bool(exp),
            "files_created": sorted((exp or {}).get("revisions", {})
                                    .get("vulnerable", {})
                                    .get("declared_expectation", "")[:0] or []) or
                                   (sorted(exp["revisions"]["vulnerable"]["harness_files"])
                                    if exp and exp["revisions"].get("vulnerable", {})
                                    .get("harness_files") is not None else []),
            "compile_result": ("compile_error" if (vuln.get("status") == "compile_error")
                               else ("ok" if vuln.get("status") in ("pass", "fail")
                                     else "not_attempted")),
            "execution_result": vuln.get("status") or "not_executed",
            "failure_reason": run_reason,
            "root_cause": vuln.get("run_failure_detail"),
            "final_verdict": level if not exp else (
                "l6_verified_patch" if exp.get("verdict") == "l6_verified_patch"
                else "reproduced_not_blocked"
                if exp.get("verdict") == "reproduced_but_not_blocked"
                else "exploit_not_reproduced"
                if exp.get("verdict") == "exploit_not_reproduced_on_vulnerable_revision"
                else "inconclusive"),
        })

    write_jsonl(Path(args.out_log), log_rows)

    # ---- manifest: what a third party needs in order to replay each experiment
    manifest = []
    for fid, exp in sorted(experiments.items()):
        for label, rev in exp.get("revisions", {}).items():
            art = rev.get("artifact")
            rj = None
            if art:
                p = Path(art) / "result.json"
                if p.exists():
                    import json
                    rj = json.loads(p.read_text(encoding="utf-8"))
            manifest.append({
                "finding_id": fid,
                "revision_label": label,
                "repository": (rj or {}).get("repository", {}),
                "commit_sha": rev.get("commit"),
                "toolchain": {"forge": "1.8.3", "solc": "selected by the repository",
                              "git": "2.55", "node": "not required (Foundry)"},
                "command": (rj or {}).get("command"),
                "environment_requirements": (rj or {}).get("environment_requirements"),
                "fork_required": False,
                "fork_block": None,
                "result": rev.get("status"),
                "artifact_dir": str(Path(art).relative_to(ROOT)).replace("\\", "/")
                                 if art else None,
                "artifact_hashes": (rj or {}).get("artifact_sha256"),
                "harness_digest": (rj or {}).get("harness_digest"),
                "production_files_modified":
                    (rj or {}).get("forensics", {}).get("production_files_modified_count"),
            })

    stats = {
        "generated_by": "scripts/build_reproduction.py",
        "exploit_records": len(exploits),
        "poc_class_distribution": dict(classes),
        "poc_level_distribution": dict(levels),
        "poc_level_definitions": pc.POC_LEVELS,
        "poc_class_vocabulary": list(pc.POC_CLASSES),
        "failure_reason_vocabulary": list(pc.FAILURE_REASONS),
        "experiments_attempted": len(experiments),
        "experiment_outcomes": dict(Counter(
            e.get("verdict") for e in experiments.values())),
        "levels_l4_or_higher": sum(v for k, v in levels.items() if k >= "L4"),
        "levels_l5_or_higher": sum(v for k, v in levels.items() if k >= "L5"),
        "levels_l6": levels.get("L6", 0),
        "guard": ("no record is above L2 unless scripts/run_verified_experiments.py executed "
                  "something at the audited revision"),
        "per_record": per_record,
    }
    write_json(Path(args.out_stats), stats)
    write_json(Path(args.out_manifest), {
        "generated_by": "scripts/build_reproduction.py",
        "note": ("Replay instructions for every executed experiment. Fork-based entries "
                 "would require an archive RPC via VLUN_RPC_URL; none were executed "
                 "because no archive endpoint is distributed with the dataset."),
        "entries": manifest,
    })
    log(f"classes: {dict(classes)}")
    log(f"levels:  {dict(levels)}")
    log(f"experiments: {len(experiments)} -> {dict(Counter(e.get('verdict') for e in experiments.values()))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())