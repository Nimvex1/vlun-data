#!/usr/bin/env python3
"""Risk-based inventory of pipeline scripts versus run_gates.py coverage.

This is not a rule that every script must be a gate. It classifies every
`.py` file under `scripts/` and `Vbeta/scripts/`, records whether a gate
invokes it, and requires an explicit exception for production builders and
validators that can mutate labels, splits, answer keys, release manifests
or committed reports without a gate.

    python scripts/gate_coverage.py            # write reports/gate_coverage.json
    python scripts/gate_coverage.py --check    # compare, write nothing
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "reports" / "gate_coverage.json"
SCRIPT_ROOTS = (ROOT / "scripts", ROOT / "Vbeta" / "scripts")

CATEGORIES = (
    "production_builder",
    "production_validator",
    "evaluation",
    "release_rights",
    "research_harvest",
    "library",
    "legacy",
)

# Production mutation/publication paths that are allowed to sit outside
# run_gates.py. Each exception is a reason, not a skip of the inventory.
UNGATED_REASONS = {
    "scripts/run_gates.py":
        "umbrella runner; it is not a child of itself",
    "scripts/validate_checks.py":
        "implementation module of validate.py; the v1-authorship gate covers it",
    "scripts/validate_schema.py":
        "schema helper; schemas-current and validate.py cover published schemas",
    "scripts/inventory_rights.py":
        "builds rights_inventory.json; check_rights_consistency.py is the gate",
    "scripts/build_all.py":
        "orchestrator; canonical-layer guard is in-process, not a --check gate",
    "scripts/check_leakage.py":
        "--emit is a migration; in-script curated-write guard refuses "
        "quarantine shrink/empty; build_all.py still rolls back canonical rewrites",
    "scripts/build_benchmark.py":
        "rebuilds frozen family rows; gated indirectly via benchmark --check "
        "freshness of emitted task files and score_benchmark.py",
    "scripts/build_benchmark_v22.py":
        "v2.2 family builder; freshness covered by v2.2 split/manifest checks",
    "scripts/build_benchmark_v31.py":
        "family T builder; taxonomy-current / v31 gates cover the outputs",
    "scripts/build_derived.py":
        "needs local clones; canonical derived/ is guarded by build_all.py",
    "scripts/build_derived_v22.py":
        "v2.2 derived builder; split-pointer --check covers the published hashes",
    "scripts/build_v3.py":
        "needs V3/clones; validate_v3.py is the gate on the published layer",
    "scripts/normalize_v3.py":
        "needs V3/clones; validate_v31.py is the gate on the published layer",
    "scripts/resolve_citations.py":
        "needs local clones; remaining_mutable_in_source_layer is tested "
        "from jsonl/ and stored in citation_resolution.json",
    "scripts/fetch_sources.py":
        "network harvest; skipped_no_network, never a CI freshness gate",
    "scripts/verify_pocs.py":
        "execution; artefacts gated by proof-hashes / verified-experiments reports",
    "scripts/verify_patches.py":
        "execution; patch_verification.json is the published artefact",
    "scripts/run_verified_experiments.py":
        "execution; needs work/wt clones; not a --check gate",
    "scripts/build_counterexamples.py":
        "derived helper; counterexample_stats.json consumed by reports, not a gate",
    "scripts/build_hard_negatives.py":
        "derived helper; hard_negative_stats.json consumed by reports",
    "scripts/build_reproduction.py":
        "derived helper; reproduction reports are gated elsewhere",
    "scripts/build_ml_ingest.py":
        "jsonl_ml builder; check_ml_layer.py is the gate",
    "scripts/build_splits_v22.py":
        "v2.2 split builder; pointer --check covers published hashes",
    "scripts/build_subsets.py":
        "subset builder; validate.py subset admission checks are the gate",
    "scripts/build_canonical_training.py":
        "training view builder; eval-leakage is the publication gate",
    "scripts/build_vyper_ml.py":
        "language-specific ingest; ml-layer gate covers jsonl_ml/",
    "scripts/audit_records.py":
        "one-off audit writer; does not mutate labels or splits",
    "scripts/audit_pre_upgrade.py":
        "historical audit; committed report is frozen",
    "scripts/audit_third_party.py":
        "rights census helper; check_rights_consistency.py is the gate",
    "scripts/audit_sources.py":
        "source registry helper; ingest report is committed separately",
    "scripts/depth_dashboard.py":
        "coverage dashboard; field-coverage-current is the gate",
    "scripts/generate_v21_reports.py":
        "legacy v2.1 report writer; superseded by generate_reports.py",
    "scripts/generate_v22_reports.py":
        "legacy v2.2 report writer; superseded by layer-specific --check gates",
    "scripts/register_v4.py":
        "V4 registration; v4-licensing-current is the gate",
    "scripts/review_patch_candidates.py":
        "review helper; does not publish splits or labels",
    "scripts/export_run_artefacts.py":
        "artefact exporter; proof-hashes-current is the gate",
    "scripts/build_source_sha_index.py":
        "local sha index over git-ignored clones",
    "scripts/experiments.py":
        "library of experiment runners, not a publisher",
    "scripts/v32_execution.py":
        "execution helper; unblock_v32_runs --check is the gate",
}


LIBRARY = {
    "scripts/__init__.py",
    "scripts/vlun.py",
    "scripts/vlun_io.py",
    "scripts/vlun_ml.py",
    "scripts/vlun_v3.py",
    "scripts/schema_terms.py",
    "scripts/gate_inputs.py",
    "scripts/local_sources.py",
    "scripts/pdf_cmap.py",
    "scripts/pdf_decode.py",
    "scripts/pdf_text.py",
    "scripts/poc_classification.py",
    "scripts/solidity_facts.py",
    "scripts/taxonomy.py",
    "scripts/normalize_v3_lib.py",
    "scripts/prove_grader.py",
    "scripts/counterexample_pairs.py",
    "Vbeta/scripts/vlun_vbeta.py",
}

LEGACY = {
    "scripts/generate_v21_reports.py",
    "scripts/generate_v22_reports.py",
    "scripts/audit_pre_upgrade.py",
}

HARVEST = {
    "scripts/crawl_solodit.py",
    "scripts/fetch_sources.py",
    "scripts/extract_cloned_findings.py",
    "scripts/ingest_audit_sources.py",
    "scripts/build_v3_harvest.py",
    "scripts/v31_extract.py",
    "Vbeta/scripts/harvest_lisabench.py",
    "Vbeta/scripts/harvest_scabench.py",
    "Vbeta/scripts/harvest_solodit.py",
    "Vbeta/scripts/harvest_web3bugs.py",
}

RIGHTS = {
    "scripts/build_release_manifest.py",
    "scripts/check_rights_consistency.py",
    "scripts/inventory_rights.py",
    "scripts/reconcile_v4_licensing.py",
    "scripts/redact_machine_paths.py",
}

EVALUATION = {
    "scripts/benchmark_status.py",
    "scripts/score_benchmark.py",
    "scripts/score_f_extension.py",
    "scripts/score_span_tasks.py",
    "scripts/independent_benchmark_audit.py",
    "scripts/run_verified_experiments.py",
    "scripts/run_ml_pocs.py",
    "scripts/run_move_poc.py",
    "scripts/run_vyper_poc.py",
    "scripts/run_dhl_experiments.py",
    "scripts/run_negative_experiments.py",
    "scripts/run_static_analysis.py",
    "scripts/verify_pocs.py",
    "scripts/verify_patches.py",
    "scripts/experiments.py",
    "scripts/v32_execution.py",
    "scripts/unblock_v32_runs.py",
    "scripts/rerun_v1_pocs.py",
    "scripts/nonevm/aptos_move.py",
    "scripts/nonevm/cairo_scarb.py",
    "scripts/nonevm/common.py",
    "scripts/nonevm/cosmwasm.py",
    "scripts/nonevm/run_pilot.py",
    "scripts/nonevm/solana_anchor.py",
    "scripts/nonevm/sui_move.py",
}

VALIDATOR_PREFIXES = ("scripts/validate", "scripts/check_", "scripts/run_gates.py",
                      "scripts/gate_coverage.py", "Vbeta/scripts/validate_")


def list_scripts() -> list[str]:
    out = []
    for base in SCRIPT_ROOTS:
        for p in sorted(base.rglob("*.py")):
            if "__pycache__" in p.parts:
                continue
            out.append(p.relative_to(ROOT).as_posix())
    return out


def classify(rel: str) -> str:
    if rel in LIBRARY:
        return "library"
    if rel in LEGACY:
        return "legacy"
    if rel in HARVEST:
        return "research_harvest"
    if rel in RIGHTS:
        return "release_rights"
    if rel in EVALUATION:
        return "evaluation"
    if rel.startswith(VALIDATOR_PREFIXES) or any(
            rel.startswith(p) for p in VALIDATOR_PREFIXES):
        return "production_validator"
    name = Path(rel).name
    if name.startswith(("validate", "check_")) or name in (
            "run_gates.py", "gate_coverage.py"):
        return "production_validator"
    return "production_builder"


def gated_scripts() -> dict[str, list[str]]:
    sys.path.insert(0, str(ROOT / "scripts"))
    import run_gates as rg  # noqa: PLC0415
    by_script: dict[str, list[str]] = {}
    for name, cmd in rg.GATES:
        for tok in cmd:
            if not isinstance(tok, str):
                continue
            if tok.endswith(".py") and (
                    tok.startswith("scripts/") or tok.startswith("Vbeta/")):
                by_script.setdefault(tok, []).append(name)
    return by_script


def build() -> dict:
    scripts = list_scripts()
    gated = gated_scripts()
    rows = []
    missing_exception = []
    for rel in scripts:
        cat = classify(rel)
        gates = gated.get(rel, [])
        reason = UNGATED_REASONS.get(rel)
        if cat in ("production_builder", "production_validator",
                   "release_rights") and not gates and not reason:
            missing_exception.append(rel)
        rows.append({
            "path": rel,
            "category": cat,
            "gates": gates,
            "gated": bool(gates),
            "ungated_reason": reason,
        })
    by_cat = {}
    for r in rows:
        by_cat.setdefault(r["category"], 0)
        by_cat[r["category"]] += 1
    return {
        "generated_by": "scripts/gate_coverage.py",
        "description": (
            "Risk-based inventory of scripts/ and Vbeta/scripts/. Not every "
            "script is a gate. Production builders/validators/release tools "
            "that can mutate labels, splits, answer keys, manifests or "
            "committed reports must be gated or listed in UNGATED_REASONS."),
        "script_count": len(rows),
        "gated_script_count": sum(1 for r in rows if r["gated"]),
        "by_category": dict(sorted(by_cat.items())),
        "missing_ungated_reason": missing_exception,
        "scripts": rows,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    doc = build()
    if doc["missing_ungated_reason"]:
        print("gate_coverage: production script(s) have no gate and no "
              "UNGATED_REASONS entry:", file=sys.stderr)
        for rel in doc["missing_ungated_reason"]:
            print(f"  {rel}", file=sys.stderr)
        return 1
    text = json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if args.check:
        if not OUT.exists():
            print("MISSING reports/gate_coverage.json", file=sys.stderr)
            return 1
        on_disk = json.loads(OUT.read_text(encoding="utf-8"))
        if on_disk != json.loads(text):
            print("STALE reports/gate_coverage.json — run: "
                  "python scripts/gate_coverage.py", file=sys.stderr)
            return 1
        print(f"ok: gate_coverage.json ({doc['script_count']} scripts, "
              f"{doc['gated_script_count']} gated)")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote reports/gate_coverage.json ({doc['script_count']} scripts, "
          f"{doc['gated_script_count']} gated)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
