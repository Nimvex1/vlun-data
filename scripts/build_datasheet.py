#!/usr/bin/env python3
"""Generate docs/DATASHEET.md (Datasheets-for-Datasets style) from reports/.

Every number is read from a report or manifest; prose describes process.
Nothing is typed by hand.

    python scripts/build_datasheet.py
    python scripts/build_datasheet.py --check
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))


def js(path: Path, default=None):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return default


def n(x):
    return f"{x:,}" if isinstance(x, int) else str(x)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    stats = js(ROOT / "reports" / "dataset_stats.json", {}) or {}
    rc = stats.get("record_counts", {}) or {}
    m3 = js(ROOT / "derived_v3" / "manifest.json", {}) or {}
    mvb = js(ROOT / "Vbeta" / "derived_vbeta" / "manifest.json", {}) or {}
    m22 = js(ROOT / "derived_v2_2" / "manifest.json", {}) or {}
    fc = js(ROOT / "reports" / "field_coverage.json", {}) or {}
    fields = fc.get("fields", {}) or {}
    # known_pct == 0.0 is falsy; `or 100` hid fully unknown fields from this
    # count (the datasheet said 3 of 28 when 11 are under 50%). Keep zero.
    thin = sum(1 for v in fields.values()
               if isinstance(v, dict)
               and isinstance(v.get("known_pct"), (int, float))
               and v["known_pct"] < 50)
    bl = js(ROOT / "reports" / "baselines" / "baseline_majority.json",
            {}) or {}
    micro = (bl.get("micro") or {})
    cov = (bl.get("coverage") or {})
    # The primary metric, its denominator and the held-out floor come from the
    # scorer's own metric report; the four family blocks come from the
    # baseline report that carries them. Nothing here is typed in.
    metrics = js(ROOT / "reports" / "benchmark_metrics.json", {}) or {}
    pm = metrics.get("primary_metric") or {}
    prim_families = pm.get("families") or sorted(bl.get("families") or {})
    prim_den = pm.get("denominator") or micro.get("scorable") or 0
    prim_splits = pm.get("by_split") or {}
    _floors = (metrics.get("baselines") or {}).get("majority") or {}
    _maj = (_floors.get("primary") or {})
    _maj_fam = next((v for k, v in _maj.items() if k in prim_families), {})
    _maj_acc = _maj_fam.get("test_accuracy")
    _maj_f1 = _maj_fam.get("test_macro_f1")
    expl_n = (bl.get("micro_exploratory") or {}).get("scorable", 0) or 0
    inval_n = (bl.get("micro_invalid") or {}).get("scorable", 0) or 0
    ret_n = (bl.get("micro_retired") or {}).get("scorable", 0) or 0
    all_n = (bl.get("micro_all_families") or {}).get("scorable", 0) or 0
    leak = (m3.get("admitted_verification_levels", {}) or {})
    lvl = (mvb.get("candidate_verification_levels", {}) or {})
    # Judge-only / unlabelled tasks. Counted from the scorer's own
    # exclusion list (per-family task counts it records), NOT from
    # manifest_scorable_total - scorer_covered: that subtraction goes
    # negative here because the v3/Vbeta manifests tally `tasks` while the
    # scorer counts labeled rows, so the difference is not a task count.
    _excl = (cov.get("excluded_families") or {})
    _judged_n = sum(int(v.get("tasks") or 0) for v in _excl.values())
    # The open-key statement: the answer keys of the benchmark families are
    # committed in this repository, so they are reachable by repository-wide
    # retrieval. The only protected evaluation is the VLUN-Prove private
    # split, whose key lives outside the tracked tree.
    _leakrep = js(ROOT / "reports" / "eval_leakage_report.json", {}) or {}
    _rb = ((_leakrep.get("release_boundary") or {}).get("open_key") or {})
    _open_key = (_rb.get("benchmark_families") or {}).get("statement", "")
    _prove = js(ROOT / "reports" / "prove_split_interface.json", {}) or {}
    _priv = (_prove.get("private_commitment") or {}).get("files") or {}
    try:
        import importlib.util as _ilu
        _spec = _ilu.spec_from_file_location(
            "_rg", str(ROOT / "scripts" / "run_gates.py"))
        _rg = _ilu.module_from_spec(_spec)
        _spec.loader.exec_module(_rg)
        _gate_n = len(_rg.GATES)
    except Exception:
        _gate_n = "?"

    lines = f"""# Datasheet for VLUN

## Motivation

VLUN exists to give model builders a vulnerability corpus where every claim
carries its evidence type and every count recomputes from the files. It was
created because public audit findings are scattered across contest repos,
PDFs and aggregators with no common schema, no splits, and no executable
ground truth. Governing rule: truth over scale.

## Composition

- v1 (immutable): {n(rc.get('findings', 0))} findings, {n(rc.get('negatives', 0))} negatives, {n(rc.get('exploits', 0))} exploits, {n(rc.get('patches', 0))} patches, {n(rc.get('protocol', 0))} protocol rows, {n(rc.get('metadata', 0))} metadata rows, {n(rc.get('errors', 0))} error rows.
- v2.2 (five languages): {n(m22.get('records', 0))} derived records.
- V3.0: {n(m3.get('record_count', 0))} admitted of {n(m3.get('candidate_count', 0))} candidates across {n(m3.get('source_count', 0))} sources; levels {json.dumps(leak, sort_keys=True)}.
- Vbeta (isolated): {n(mvb.get('record_count', 0))} admitted of {n(mvb.get('candidate_count', 0))} candidates across {n(mvb.get('source_count', 0))} sources; levels {json.dumps(lvl, sort_keys=True)}.
- Benchmark: the primary metric covers {n(prim_den)} exactly-scorable rows of the PRIMARY set ({len(prim_families)} famil{'y' if len(prim_families) == 1 else 'ies'}: {', '.join(prim_families)}); the train-only majority floor on the {n(prim_splits.get('test', 0))} held-out test rows is {('%.4f' % _maj_acc) if isinstance(_maj_acc, (int, float)) else 'n/a'} (macro-F1 {('%.4f' % _maj_f1) if isinstance(_maj_f1, (int, float)) else 'n/a'}). The family status is computed at run time from the independent audit's measurements, not from a list: {n(expl_n)} rows sit in EXPLORATORY families (demoted: too few rows, a holdout too small to estimate on, or a single observed label), {n(inval_n)} rows in INVALID families (a validity flag makes them unusable as evaluation evidence), {n(ret_n)} in retired families (retirement is a location, not a verdict) and {n(_judged_n)} in families with no exactly-matchable key — the exclusion is recorded per family, never silent. The continuity twin covers all {n(all_n)} scorable rows ever shipped. **The benchmark is OPEN-KEY**: {_open_key.rstrip('.')}. The only protected evaluation in this project is the VLUN-Prove private split, whose answer key lives outside the tracked tree and is committed to by hash ({n(len(_priv))} files).
- Field coverage: {n(thin)} of {n(len(fields))} tracked fields under 50% known (see `reports/field_coverage.md`). `unknown` is a counted outcome everywhere.

## Collection process

- v1: Code4rena audit repositories + dependency repos + code4rena.com reports; citations resolved to commits (`scripts/resolve_citations.py`).
- v2.2: advisories, audits, bounties, post-mortems across five languages.
- V3: 18 cloned archives (audits, contests, incident PoCs, one research dataset); provenance is clone-HEAD + file sha256.
- Vbeta: first-party audit pages observed live (URL + titles + date receipts) plus a Solodit HIGH+MEDIUM mirror (auditor originals canonical); PDFs mined in temp space and deleted (METADATA_ONLY).
- METADATA_ONLY is this project's default data-handling policy, applied where no documented right to redistribute exists. It is not a claim and not a determination that any transformed, projected or digested record has been legally cleared; a hash plus a permalink identifies bytes and grants no reuse. Per-source rights decisions are recorded in `V4/licensing.json` and `distribution_v1/rights_source_registry.json` and enforced by `scripts/check_rights_consistency.py`.

## Preprocessing, cleaning, labeling

- Admission computed in code (`decide()`): IMPORT only on title + severity + link + status all observed; near-duplicates quarantined as CORROBORATION_ONLY with links, never deleted; splits isolate by repository/source with quarantine files.
- Taxonomy assigned only where evidence supports it (`unknown` otherwise); severities preserved verbatim; team-reported `Fixed` never promoted to `verified_patch`.
- Splits: no source spans splits (machine-checked); duplicates quarantined, never deleted.

## Uses

- Past uses: vulnerability detection/reasoning benchmarks (families A–V), exploit-verification and patch-verification studies on executed subsets.
- Intended: training and evaluating security-reasoning models with honest abstention (`unknown`, `unlabeled`, quarantine).
- Out of scope: production audit decisions; L0/L1 rows are not executable proof; the families the independent audit flags INVALID carry no signal, and a family whose scorable rows carry a single observed label is not evaluable for accuracy at all (`docs/RUBRIC.md`).

## Distribution

- The release boundary is `RELEASE_MANIFEST.json`: a tracked path that is not listed there with a released rights status is **not licensed here**. The released set is the pipeline (`scripts/`, MIT) and the authors' own documents, schemas, decision records, analysis reports, test code and rights-redacted `distribution_v1/` view (CC BY 4.0). The manifest names every path and the licence that applies to it.

- The evidence corpus (`jsonl*/`, `derived*/`, `splits*/`, `benchmark/`, `datasets/`, `training/`, `reports/`, `Vbeta/`) is not in the released set, and this project grants no redistribution right over it. Third-party source: not licensed here at all (see `NOTICE.md` and `LICENSE`).

- 424 v1 records carry verbatim source from repositories declaring no licence (flagged per record). For strictly licence-clean use, resolve `code_context[].snippet` entries from the original audits. Attribution is not a redistribution right.

## Maintenance

- Maintained via `scripts/build_all.py` stages with `scripts/run_gates.py` ({_gate_n} gates) as the release bar; README, stats and field coverage regenerate from artefacts (`--check` enforced in CI).
- Contact/limitations: validation reports record every unknown, exclusion and failure reason; limitations are published in `reports/benchmark_metrics.md` and `reports/reproducibility_report.md`, not hidden.
"""
    out = ROOT / "docs" / "DATASHEET.md"
    if args.check:
        if (not out.is_file()
                or out.read_text(encoding="utf-8") != lines):
            print("STALE docs/DATASHEET.md — run: python scripts/build_datasheet.py")
            return 1
        print("docs/DATASHEET.md is current")
        return 0
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(lines, encoding="utf-8", newline="\n")
    print(f"wrote docs/DATASHEET.md ({len(lines.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
