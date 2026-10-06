#!/usr/bin/env python3
"""Run the whole pipeline, in dependency order.

    python scripts/build_all.py               # everything that can run offline-safe
    python scripts/build_all.py --with-network   # also clone repos and run PoCs
    python scripts/build_all.py --from 4        # resume at stage 4

Stages that cannot run — no network, no clone, no archive RPC — emit a
deterministic machine-readable status instead of being silently skipped, and the
final gate still runs so the build reports honestly.

Stage order matters: sources must exist before anything can analyse them, and
statistics must be regenerated before the gate compares them.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vlun import REPORTS, ROOT, WORK, log, write_json  # noqa: E402

PY = sys.executable

# Stages allowed to fail without failing the build. Empty by default: a stage that
# fails means a downstream artefact is stale or missing, and shipping that as a
# green build is the failure mode this constant exists to prevent. If a stage ever
# genuinely cannot fail the build, add it here with a comment saying why.
TOLERATED_FAILURES: set[str] = set()

STAGES = [
    # (id, needs network, script, args, description)
    (1, True, "fetch_sources.py", ["--checkouts"],
     "clone the audited repositories and retrieve every pinned (commit, file) citation"),
    (2, False, "build_derived.py", [],
     "evidence semantics, attacker model, state transition, expanded code context, taxonomy"),
    (3, False, "build_hard_negatives.py", [], "structured rejection reasons for the negative corpus"),
    (4, False, "build_counterexamples.py", [],
     "nearby false hypotheses for confirmed High/Medium findings"),
    # Reads the clones stage 1 produced and resolves by local git plumbing
    # (blob identity, submodule pointer, date-anchored blob). It does NOT touch
    # the network, so it must run offline whenever the clones are present -
    # otherwise an offline rebuild silently unpins every citation.
    (5, False, "resolve_citations.py", [],
     "replace every mutable branch citation with the commit that holds the cited content"),
    (6, True, "run_verified_experiments.py", [],
     "execute the declared exploit experiments against pinned revisions"),
    (7, True, "run_negative_experiments.py", [],
     "attempt the attack each hard negative claims, at the audited revision"),
    (8, True, "verify_pocs.py", [], "compile and execute the remaining PoCs"),
    (9, False, "verify_patches.py", [],
     "vulnerable vs fixed revision pairs, plus the patch delta classification"),
    (10, False, "classify_negatives.py", [],
     "four-class negative taxonomy with duplicate corroboration"),
    (11, False, "build_reproduction.py", [],
     "PoC class + L-level distribution, reconstruction log, replay manifest"),
(12, True, "run_static_analysis.py", [],
     "Slither as an independent signal, where the repository builds"),
    (13, False, "audit_third_party.py", ["--sample", "20"],
     "measure what third-party source is actually redistributed, and disclose it"),
    (14, False, "export_run_artefacts.py", [],
     "commit the executed-PoC run records out of git-ignored work/"),
    (15, False, "build_counterexamples.py", [],
     "structural refutations and API-sibling guard pairs"),
    (16, False, "check_leakage.py", ["--emit", "splits_v2"],
     "leakage detection and a leakage-free re-split"),
    (17, False, "build_benchmark.py", [], "benchmark task families A-J (v1 layer)"),
    (18, False, "build_benchmark_v22.py", [],
     "benchmark task families K-Q over derived_v2_2 + splits_v2_2, merged into the manifest"),
    (19, False, "build_subsets.py", [], "high-confidence subsets and task training files"),
    (20, False, "generate_stats.py", [], "recompute every statistic from the canonical JSONL"),
    (21, False, "audit_records.py", ["--derive"],
     "per-record evidence/quality matrix for a curator"),
    (22, False, "generate_reports.py", [], "extraction errors, benchmark metrics, final report"),
    (23, False, "generate_v21_reports.py", [], "the v2.1 BEFORE/AFTER report, benchmark/provenance/leakage quality reports"),
    (24, False, "generate_v22_reports.py", [],
     "reports/v2_2/: the five-language layer summary, benchmark A-Q and quality report"),
    (25, False, "ingest_audit_sources.py", [],
     "authoritative audit-source registry, section-4 ingestion records and "
     "reports/audit_source_ingestion_report.md (offline-safe without --probe-urls)"),
    (26, False, "build_v3.py", [],
     "V3 layer: harvest the 18 V3/clones sources into jsonl_v3/, derived_v3/, "
     "splits_v3/, benchmark families R/S and reports/v3/ (fails fast if "
     "V3/clones is not populated; never touches v1/v2.2 artefacts)"),
    (27, False, "validate_v3.py", [], "the V3 gate"),
    (28, False, "normalize_v3.py", [],
     "V3.1 evidence extraction: finding boundaries, field evidence, "
     "taxonomy, overlays, preview, readiness (fails fast if V3/clones is "
     "not populated; never rewrites v3.0 files)"),
    (29, False, "validate_v31.py", [], "the V3.1 normalization gate"),
    (30, False, "build_benchmark_v31.py", [],
     "benchmark family T (explicit-confidence taxonomy) + v3 manifest"),
    (31, False, "generate_readme.py", [],
     "README.md and NOTICE.md, with every figure read from the reports"),
    (32, False, "validate.py", [], "the gate"),
]


def _scrub(text: str) -> str:
    """Strip local paths and home directories out of captured build output.

    Subprocess stderr routinely contains absolute paths and the operator's home
    directory. Those end up in a committed report, which leaks nothing useful and
    makes the build non-reproducible, so they are replaced with placeholders.
    """
    if not text:
        return ""
    t = text.replace(str(ROOT), "<repo>").replace(str(ROOT).replace("\\", "/"), "<repo>")
    home = str(Path.home())
    for h in {home, home.replace("\\", "/")}:
        if h and h not in ("/", "C:\\"):
            t = t.replace(h, "<home>")
    return re.sub(r"[A-Za-z]:[\\/][^\s\"'<>|]*", "<path>", t)


def run_stage(nid: int, script: str, args: list[str], desc: str, needs_net: bool,
              allow_net: bool) -> dict:
    cmd = [PY, str(ROOT / "scripts" / script), *args]
    # Record the command as a user would type it. The resolved interpreter path is
    # machine-specific and must not be committed.
    shown = " ".join(["python", f"scripts/{script}", *args])
    t0 = time.time()
    if needs_net and not allow_net:
        return {"stage": nid, "script": script, "status": "skipped_no_network",
                "reason": "this stage needs network access; re-run with --with-network",
                "seconds": 0, "command": shown}
    proc = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True, errors="replace")
    out = (proc.stdout or "").strip().splitlines()
    return {
        "stage": nid, "script": script, "status": "ok" if proc.returncode == 0 else "failed",
        "rc": proc.returncode, "seconds": round(time.time() - t0, 1),
        "command": shown, "description": desc,
        "tail": _scrub("\n".join(out[-40:])),
        "stderr_tail": _scrub("\n".join((proc.stderr or "").strip().splitlines()[-15:])),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--with-network", action="store_true",
                    help="also clone repositories and execute PoCs")
    ap.add_argument("--from", dest="start", type=int, default=1)
    ap.add_argument("--to", dest="end", type=int, default=len(STAGES))
    ap.add_argument("--continue-on-failure", action="store_true", default=True)
    args = ap.parse_args()

    results = []
    log("build_all")
    for nid, needs_net, script, sargs, desc in STAGES:
        if not (args.start <= nid <= args.end):
            continue
        log(f"\n=== stage {nid}: {script} — {desc}")
        r = run_stage(nid, script, sargs, desc, needs_net, args.with_network)
        results.append(r)
        log(f"  -> {r['status']}" + (f" rc={r['rc']}" if "rc" in r else "") +
            f" ({r['seconds']}s)")
        for line in (r.get("tail") or "").splitlines()[-12:]:
            log(f"     {line}")

    summary = {
        "generated_by": "scripts/build_all.py",
        "stages": results,
        "by_status": {s: sum(1 for r in results if r["status"] == s)
                      for s in sorted({r["status"] for r in results})},
    }
    write_json(REPORTS / "build_all.json", summary)
    log(f"\nbuild_all.json: {summary['by_status']}")

    # A stage that failed may have left downstream artefacts stale or absent.
    # Reporting success here is how a broken build ships as a green pipeline, so
    # any failure is fatal unless it is explicitly tolerated above.
    failed = [r for r in results if r["status"] == "failed"]
    if failed:
        tolerated = ({r["script"] for r in failed if r["script"] in TOLERATED_FAILURES}
                     if TOLERATED_FAILURES else set())
        hard = [r for r in failed if r["script"] not in tolerated]
        if hard:
            for r in hard:
                log(f"STAGE FAILED: stage {r['stage']} {r['script']} rc={r.get('rc')}")
            if tolerated:
                log(f"  (tolerated: {sorted(tolerated)})")
            skipped_here = summary["by_status"].get("skipped_no_network", 0)
            if skipped_here and not args.with_network:
                log("")
                log(f"{skipped_here} stage(s) were skipped because --with-network was not")
                log("given. Those stages provide the clone, execution and citation-resolution")
                log("inputs the later stages depend on, so an offline run cannot produce a")
                log("complete or self-consistent dataset. Re-run with:")
                log("    python scripts/build_all.py --with-network")
            log("BUILD FAILED")
            return 1

    gate = next((r for r in results if r["script"] == "validate.py"), None)
    gate_v3 = next((r for r in results if r["script"] == "validate_v3.py"), None)
    gate_v31 = next((r for r in results if r["script"] == "validate_v31.py"),
                    None)
    if gate and gate["status"] != "ok":
        log("GATE FAILED")
        return 1
    if gate_v3 and gate_v3["status"] != "ok":
        log("V3 GATE FAILED")
        return 1
    if gate_v31 and gate_v31["status"] != "ok":
        log("V3.1 GATE FAILED")
        return 1
    skipped = summary["by_status"].get("skipped_no_network", 0)
    if skipped:
        log(f"pipeline complete, but {skipped} stage(s) were skipped for lack of network")
        log("  artefacts that depend on them are NOT reproduced by this run")
    else:
        log("pipeline complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())