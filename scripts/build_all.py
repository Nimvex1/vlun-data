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
import hashlib
import re
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vlun import REPORTS, ROOT, log, write_json  # noqa: E402

PY = sys.executable

# Stages allowed to fail without failing the build. Empty by default: a stage that
# fails means a downstream artefact is stale or missing, and shipping that as a
# green build is the failure mode this constant exists to prevent. If a stage ever
# genuinely cannot fail the build, add it here with a comment saying why.
TOLERATED_FAILURES: set[str] = set()

# Published layers whose committed bytes consumers (splits, benchmark, reports,
# citations) are pinned to. A whole-tree build re-runs every generator, so a
# stage-ordering difference shows up here as a rewrite of data that was not
# asked to change. Such a rewrite is restored and reported, never absorbed
# quietly; an intentional refresh is an explicit, reviewed migration and needs
# --allow-canonical-rewrite.
CANONICAL_LAYERS = (
    "derived/records.jsonl", "derived/manifest.json",
    "derived/hard_negatives.jsonl", "derived/counterexamples.jsonl",
    "derived/root_cause_candidates.jsonl",
    "splits_v2/train.jsonl", "splits_v2/validation.jsonl",
    "splits_v2/test.jsonl", "splits_v2/quarantine.jsonl",
    # Measured on the pre-emit splits: stage 16 quarantines the pairs it finds,
    # so re-running it against its own output reports zero leakage and train
    # 413 instead of 415. That number is the evidence the quarantine exists,
    # so it is guarded with the layer it describes.
    "reports/leakage_report.json",
    # The same failure mode, found by auditing a build run on a checkout that
    # holds none of the git-ignored inputs: the generator recomputed from what it
    # could read and published a SMALLER truth.
    # `derived_prove/candidate_ledger.jsonl` went 210 -> 38 rows, and every lost
    # row carried its own licence, poc-path and rights fields;
    # `reports/citation_resolution.json` lost all 473 pinned commits;
    # `reports/counterexample_stats.json` went 99 -> 12 counterexamples and
    # 71 -> 0 API-sibling pairs, which README then asserted as a zero in prose.
    # A count that can only move downward when an input is missing is not a
    # measurement, so it is guarded with the layer it describes.
    "derived_prove/candidate_ledger.jsonl",
    "reports/citation_resolution.json", "reports/counterexample_stats.json",
    "reports/prove_candidate_ledger.json", "reports/prove_candidate_ledger.md",
)


def _layer_hashes(paths) -> dict[str, str]:
    out = {}
    for rel in paths:
        p = ROOT / rel
        if p.is_file():
            out[rel] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def guard_canonical_layers(stage: int, script: str, start_bytes: dict[str, bytes],
                           allow_rewrite: bool) -> list[tuple[str, dict]]:
    """Restore published layers a stage rewrote; report what it tried to do.

    Returns the (path, record) pairs it blocked. `allow_rewrite` leaves the new
    bytes in place — that is the reviewed-migration path, not the default.
    """
    blocked = []
    after = _layer_hashes(start_bytes)
    for rel in sorted(set(start_bytes) | set(after)):
        want = start_bytes.get(rel)
        if want is None or hashlib.sha256(want).hexdigest() == after.get(rel):
            continue
        rec = {"stage": stage, "script": script,
               "before": hashlib.sha256(want).hexdigest(),
               "after": after.get(rel), "restored": not allow_rewrite}
        if not allow_rewrite:
            (ROOT / rel).write_bytes(want)
        blocked.append((rel, rec))
    return blocked


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
    (10, False, "build_rejection_corpus.py", [],
     "canonical rejection-evidence axes for all 458 negatives (six independent metrics)"),
    (11, False, "classify_negatives.py", [],
     "report-side view of the rejection corpus; derives nothing itself"),
    (12, False, "build_reproduction.py", [],
     "PoC class + L-level distribution, reconstruction log, replay manifest"),
(13, True, "run_static_analysis.py", [],
     "Slither as an independent signal, where the repository builds"),
    (14, False, "audit_third_party.py", ["--sample", "20"],
     "measure what third-party source is actually redistributed, and disclose it"),
    (15, False, "export_run_artefacts.py", [],
     "commit the executed-PoC run records out of git-ignored work/"),
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
    (31, True, "run_dhl_experiments.py", ["--max-attempts", "6"],
     "V3.2 DeFiHackLabs pilots: staged build + fork execution with full "
     "artefacts (needs network for forge-std/solc fetches and fork RPC)"),
    (32, False, "build_f_extension.py", [],
     "F-extension over the v1 rejection corpus: F-A six-axis evidence vectors and "
     "F-B duplicate-radar pairs, merged into benchmark/manifest.json"),
    (33, False, "score_f_extension.py", ["--baselines"],
     "the trivial predictors a model must beat on the F-extension denominators"),
    (34, False, "build_prove_ledger.py", [],
     "VLUN-Prove candidate ledger: recorded two-revision evidence plus discovered "
     "candidates, policed against the admission-gate fields"),
    (35, False, "generate_readme.py", [],
     "README.md and NOTICE.md, with every figure read from the reports"),
    (36, False, "validate.py", [], "the gate"),
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
    ap.add_argument("--allow-canonical-rewrite", action="store_true",
                    help="let stages rewrite published split/derived layers "
                         "instead of restoring the bytes they started with "
                         "(use only for a reviewed, documented migration)")
    args = ap.parse_args()

    results = []
    blocked_rewrites: dict[str, dict] = {}
    start_bytes = {rel: (ROOT / rel).read_bytes()
                   for rel in CANONICAL_LAYERS if (ROOT / rel).is_file()}
    log("build_all")
    for nid, needs_net, script, sargs, desc in STAGES:
        if not (args.start <= nid <= args.end):
            continue
        log(f"\n=== stage {nid}: {script} — {desc}")
        r = run_stage(nid, script, sargs, desc, needs_net, args.with_network)
        for rel, rec in guard_canonical_layers(nid, script, start_bytes,
                                                args.allow_canonical_rewrite):
            if rec["restored"]:
                log(f"     BLOCKED canonical rewrite of {rel} by stage {nid} "
                    f"({script}); bytes restored to the state this build "
                    "started with. Re-run with --allow-canonical-rewrite only "
                    "as a reviewed migration.")
            blocked_rewrites.setdefault(rel, rec)
        results.append(r)
        log(f"  -> {r['status']}" + (f" rc={r['rc']}" if "rc" in r else "") +
            f" ({r['seconds']}s)")
        for line in (r.get("tail") or "").splitlines()[-12:]:
            log(f"     {line}")

    summary = {
        "generated_by": "scripts/build_all.py",
        "stages": results,
        "canonical_layer_rewrites_blocked": blocked_rewrites,
        "canonical_rewrite_allowed": bool(args.allow_canonical_rewrite),
        "by_status": {s: sum(1 for r in results if r["status"] == s)
                      for s in sorted({r["status"] for r in results})},
    }
    write_json(REPORTS / "build_all.json", summary)
    log(f"\nbuild_all.json: {summary['by_status']}")

    if blocked_rewrites and not args.allow_canonical_rewrite:
        for rel, rec in sorted(blocked_rewrites.items()):
            log(f"CANONICAL REWRITE BLOCKED: {rel} — stage {rec['stage']} "
                f"{rec['script']} would have replaced the published bytes "
                f"(sha {str(rec['before'])[:12]} -> {str(rec['after'])[:12]}); "
                "restored")
        log("  this build cannot refresh published split/derived layers. A "
            "whole-tree rebuild is not idempotent over them, so the drift is "
            "reported instead of absorbed; refresh needs an explicit "
            "--allow-canonical-rewrite migration.")
        return 1

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