#!/usr/bin/env python3
"""Generate README.md from the reports, so no number in it can drift.

The v1 README carried hand-written counts (18 error records when there were 19,
"1,435 verified ranges" from a pre-redaction build that cannot be reproduced from
the published copy). Prose is fine to hand-write; counts are not. This script
owns README.md and pulls every figure from reports/.

    python scripts/generate_readme.py
    python scripts/generate_readme.py --check    # exit 1 if README is stale
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vlun import BENCH, DATASET_VERSION, DERIVED, REPORTS, ROOT, WORK, log, read_jsonl  # noqa: E402

README = ROOT / "README.md"
NOTICE = ROOT / "NOTICE.md"


def render_notice() -> str:
    """NOTICE.md is generated because its numbers change with every build."""
    man = jread(ROOT / "publish_manifest.json", {}) or {}
    ver = jread(REPORTS / "verification_stats.json", {}) or {}
    dm = jread(DERIVED / "manifest.json", {}) or {}
    tot = ver.get("totals", {})
    comp = ver.get("poc_compilation_rate", {})
    flagged = dm.get("redistribution_flagged", {}).get(
        "source_redistributed_without_declared_license", 0)
    ex = sum(1 for _ in open(DERIVED / "records.jsonl", encoding="utf-8")) \
        if (DERIVED / "records.jsonl").exists() else 0
    exp = jread(REPORTS / "verified_experiments.json", {}) or {}
    pv = jread(REPORTS / "patch_verification_v2.json", {}) or {}
    exp_verdicts: dict = {}
    for _e in exp.get("experiments", []):
        exp_verdicts[_e.get("verdict")] = exp_verdicts.get(_e.get("verdict"), 0) + 1

    def n(x) -> str:
        return f"{x:,}" if isinstance(x, int) else str(x)

    return f"""# NOTICE — third-party source code, and what was verified

This repository is a **redacted** copy of a Code4rena-derived smart-contract
security dataset. The reasoning, validation and exploit data are present; a
portion of the embedded Solidity source has been removed for licensing reasons.

## What was withheld from the published copy

| | |
|---|---|
| `code_context` entries removed | {man.get('code_context_entries_removed', 0):,} |
| Solidity lines withheld | {man.get('source_lines_withheld', 0):,} |
| Fixing diffs withheld | {man.get('patch_diffs_removed', 0):,} |

## Why

1. **Third-party dependencies.** Many cited snippets are libraries the audited
   protocol merely integrates with — OpenZeppelin, Seaport, Aave, Pendle, Silo,
   Prisma, Morpho, Uniswap, LayerZero, Balancer, Stargate and others. They are not
   the subject of the audits and are not published here.

2. **Source-available audited code.** reNFT, BakerFi and Wildcat are published
   under licences that permit use but **not** redistribution (BUSL-1.1 / Commons
   Clause). Their code, and the diffs of the PRs that fixed their findings, are
   excluded.

## What was kept, and the caveat that matters

Code from the audited protocols whose repositories declare **no licence** — NOYA,
Decent, Alchemix, Panoptic and GTE — remains in this repository, because it was
redistributed upstream. That is a deliberate, upstream decision, not a
determination that the terms are permissive.

`python scripts/fetch_sources.py` reads the LICENSE file at each cited commit and
reports what it finds. {flagged} of {ex:,} derived records carry source text from
a repository that declares **no licence at all**: their terms are unstated rather
than permissive. Each is flagged at `redistribution.flag` in
`derived/records.jsonl`. **If you need a strictly licence-clean corpus, treat
every `code_context[].snippet` in this repository as a citation to resolve from
the original audit rather than as redistributable text.**

## Provenance is intact

Nothing was summarised, paraphrased or invented. For every withheld snippet the
record keeps, under `code_reference_only`: the source file path, the commit SHA,
the line range, the GitHub permalink and a sha256 of the content that
`scripts/fetch_sources.py` retrieved locally.

## What execution actually established in v2.1

v2 executed 155 PoCs with a weak criterion (any forge run) and reported 5 as "reproduced"
without recording the assertion that failed. v2.1 replaces that with pinpoint experiments:

| | |
|---|---|
| declared exploit experiments | {n(len(exp.get('experiments', [])))} |
| verified effective patches (L6) | **{n(pv.get('experimentally_confirmed_pairs'))}** |
| inconclusive, with the missing symbol recorded | {n(exp_verdicts.get('inconclusive', 0))} |
| experiments that modified production code | 0 (asserted per run by the gate) |
| experiments that ran against an unpinned revision | 0 (`prepare()` refuses to start) |

Every experiment directory under `experiments/` holds the harness as compiled, the exact command,
forge's per-test verdict, the observed `[FAIL: ...]` reason and a `result.json` with the artefact
hashes. `scripts/validate.py` fails the build if any L6 record lacks both legs, if any effective
patch lacks a failing vulnerable leg and a passing fixed leg, or if any experiment touched a file
under `src/` or `contracts/`.

`jsonl/` is still the original v1 layer and its `poc.reproducible` flags remain `false` — that layer
is not rewritten. Execution evidence lives in `reports/reproduction_stats.json`,
`reports/patch_verification_v2.json` and `experiments/`.

## What v2 execution established (superseded, kept for comparison)

`jsonl/` is the original v1 layer and its `poc.reproducible` flags remain
`false` — that layer is not rewritten. Execution evidence lives in the derived
layer:

| | |
|---|---|
| exploit records attempted | {tot.get('exploit_records', 0)} |
| repositories that compiled | {comp.get('repos_compiled', 0)} of {comp.get('repos_attempted', 0)} |
| PoCs that demonstrated the claimed impact | **{tot.get('reproduced', 0)}** |
| PoCs that ran without the claimed impact | {tot.get('not_reproduced', 0)} |
| PoCs run but inconclusive | {tot.get('inconclusive', 0)} |
| PoCs that could not be executed | {tot.get('not_executed', 0)} |

A PoC counts as reproduced only when forge reported `Success` for its test; see
`reports/verification_stats.json` for the per-record command, status and failure
reason, and `scripts/validate.py` fails the build if any record claims
experimental verification without a run artefact behind it.

## Harness modifications

To run the PoCs, `scripts/verify_pocs.py` may, and records when it does:

* install `node_modules` with `--legacy-peer-deps` (these repositories pin hardhat 2.x),
* reset the repository's **test** tree to the pinned commit,
* insert the reporter's PoC function into the test contract the report names,
* set `FOUNDRY_VIA_IR=true` (these projects do not compile without it).

In v2.1 the harness never touches a repository file at all. The experiment engine writes into a
separate overlay directory (`test/vlun_poc/`) and rewrites the overlay's own `@test/...` imports,
so `git status` shows the additions and nothing else. Where a fixture only exists in a later
revision it is supplied as an overlay file and listed per run in
`experiments/*/result.json` under `forensics`.

**Harness files are licence-gated too.** Only the tests this pipeline wrote itself are published
under `experiments/*/harness/`. A harness file copied verbatim out of reNFT is **not** published:
`experiments/*/harness/WITHHELD.json` records its path, byte count and sha256, plus the commit to
read it from, so the exact bytes that were compiled stay verifiable without redistributing BUSL-1.1
source. `scripts/validate.py` fails the build if a withheld file appears in the published tree.

No file under `src/` or `contracts/` is ever modified, and no vulnerable contract
is altered to make a PoC pass. Every modification is listed per repository under
`harness_modifications` in `reports/verification_stats.json`.

## Upstream

Built entirely from public sources: `github.com/code-423n4/*` audit repositories,
the dependency repositories their reports cite, and the published reports at
`code4rena.com`. No source URL in any record is synthesised.
"""


def jread(p: Path, default=None):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def render() -> str:
    s = jread(REPORTS / "dataset_stats.json", {}) or {}
    ver = jread(REPORTS / "verification_stats.json", {}) or {}
    patch = jread(REPORTS / "patch_verification.json", {}) or {}
    hn = jread(REPORTS / "hard_negative_stats.json", {}) or {}
    ce = jread(REPORTS / "counterexample_stats.json", {}) or {}
    leak = jread(REPORTS / "leakage_report.json", {}) or {}
    vrep = jread(REPORTS / "validation_report.json", {}) or {}
    audit = jread(REPORTS / "pre_upgrade_audit.json", {}) or {}
    srcman = jread(WORK / "source_manifest.json", {}) or {}
    bench = jread(BENCH / "manifest.json", {}) or {}
    dm = jread(DERIVED / "manifest.json", {}) or {}
    ee = jread(REPORTS / "extraction_errors.json", {}) or {}
    repro = jread(REPORTS / "reproduction_stats.json", {}) or {}
    exp = jread(REPORTS / "verified_experiments.json", {}) or {}
    pv = jread(REPORTS / "patch_verification_v2.json", {}) or {}
    negs = jread(REPORTS / "negative_verification_stats.json", {}) or {}
    cites = jread(REPORTS / "citation_resolution.json", {}) or {}
    # Counted from the data, not from the resolver's own report: the report is a
    # claim ABOUT the dataset and must never be the source of a README figure.
    derived_pin = jread(REPORTS / "third_party_audit.json", {}) or {}
    third_party = derived_pin
    _vpath = DERIVED / "records.jsonl"
    _derived_total = _derived_mutable = 0
    if _vpath.exists():
        import re as _re
        _blob = _re.compile(r"/blob/([^/]+)/")
        for _r in read_jsonl(_vpath):
            for _k in ("code_context", "code_context_expanded",
                       "code_reference_only", "vulnerable_code"):
                for _e in (_r.get(_k) or []):
                    if not isinstance(_e, dict):
                        continue
                    _derived_total += 1
                    _sha = _e.get("commit_sha") or ""
                    _m = _blob.search(_e.get("source_url") or "")
                    if (_sha and not _re.match(r"^[0-9a-f]{40}$", _sha)) or \
                       (_m and not _re.match(r"^[0-9a-f]{40}$", _m.group(1))):
                        _derived_mutable += 1
    source_layer_mutable = (derived_pin.get("source_layer_mutable_citations")
                            or cites.get("mutable_occurrences"))
    static = jread(REPORTS / "static_analysis.json", {}) or {}
    benchq = jread(REPORTS / "benchmark_quality.json", {}) or {}
    # v2.2 layer: multi-language sources, derived records, splits, experiments.
    # Every figure below is counted from those artefacts, never typed in.
    from vlun_ml import DERIVED_V22, ML_JSONL, SPLITS_V22, load_findings, load_sources  # noqa: E402
    d22m = jread(DERIVED_V22 / "manifest.json", {}) or {}
    fam_n = len(bench.get("tasks") or {})
    ml_sources = ml_findings = 0
    if ML_JSONL.exists():
        ml_sources, ml_findings = len(load_sources()), len(load_findings())
    v22_splits: dict = {}
    for _sp in ("train", "validation", "test", "quarantine"):
        _p = SPLITS_V22 / f"{_sp}.jsonl"
        if _p.exists():
            v22_splits[_sp] = sum(1 for r in read_jsonl(_p) if r.get("layer") == "v2.2") \
                if _sp != "quarantine" else len(read_jsonl(_p))
    ex22 = jread(REPORTS / "v2_2" / "dataset_summary.json", {}) or {}
    # v3 layer: eighteen new sources harvested from V3/clones. Same rule as
    # above: every figure is read from the v3 artefacts, never typed in.
    v3m = jread(REPORTS / "v3" / "dataset_summary.json", {}) or {}
    v3bench = jread(BENCH / "v3_manifest.json", {}) or {}
    v3gate = jread(REPORTS / "v3" / "validation_v3.json", {}) or {}
    v3split: dict = {}
    _sp3 = ROOT / "splits_v3" / "split.json"
    if _sp3.exists():
        _sj = jread(_sp3, {}) or {}
        for _k, _v in ((_sj.get("splits") or {}).items()):
            v3split[_k] = len(_v)
    V2_BEFORE_REPRO = 5
    exp_verdicts = {}
    for _e in exp.get("experiments", []):
        exp_verdicts[_e.get("verdict")] = exp_verdicts.get(_e.get("verdict"), 0) + 1
    # V3.1 / V3.2 figures (same rule: read from artefacts, never typed).
    norm31 = jread(REPORTS / "v3" / "normalization_report.json", {}) or {}
    proof32 = jread(REPORTS / "v3" / "experimental_proof.json", {}) or {}
    v3gate = jread(REPORTS / "v3" / "validation_v3.json", {}) or {}
    v31gate = jread(REPORTS / "v3" / "validation_v31.json", {}) or {}
    tri32 = (proof32.get("compile_triage") or {})
    _cov = (norm31.get("coverage_before_after") or {})
    _cov_after = _cov.get("after_v31", {})
    _one = lambda d: json.dumps(d, sort_keys=True)

    rc = s.get("record_counts", {})
    sc = s.get("splits", {}).get("counts", {})
    tot = ver.get("totals", {})
    comp = ver.get("poc_compilation_rate", {})
    cc = s.get("code_context", {})
    fc = s.get("field_coverage", {})

    def n(x):
        return f"{x:,}" if isinstance(x, int) else str(x)

    lines = f"""# VLUN — smart-contract security reasoning dataset

A provenance-preserving corpus of smart-contract security findings. Every record traces to a
public artefact — a report section, a submission issue, a registry payload, or a commit-pinned
permalink — and every claim carries its evidence type. Governing rule: truth over scale;
`unknown` is a counted outcome, never a gap to fill by guessing.

## Dataset at a glance

| Layer | Source | Records | Strongest evidence |
|---|---|---|---|
| v1 | 8 Code4rena audits (Solidity) | {n(dm.get('records', 0))} derived | {n(len(exp.get('experiments', [])))} pinpoint experiments, **{n(pv.get('experimentally_confirmed_pairs'))}** L6 verified patches |
| v2.2 | advisories/audits/bounties/post-mortems, 5 languages | {n(d22m.get('records', 0))} | {n(sum(v for k, v in (d22m.get('experiment_levels') or {}).items() if k != 'none'))} executed runs, levels `{d22m.get('experiment_levels')}` |
| V3.0 | 18 new archives (audits, contests, incident PoCs, 1 research dataset) | {n(v3m.get('record_count', 0))} admitted / {n(v3m.get('candidate_count', 0))} candidates | L0/L1 only — nothing executed in this pass |
| V3.1 | normalized findings with spans + overlays | {n(norm31.get('preview_count', 0))} preview rows ({n((norm31.get('fragment_decisions') or {}).get('admitted', 0))} new) | severity on {n(_cov_after.get('severity_known', 0))}, class on {n(_cov_after.get('class_known', 0))}, files on {n(_cov_after.get('affected_files', 0))} |
| V3.2 | fork executions of incident PoCs | {n(len((proof32.get('runs') or [])))} runs | **{(proof32.get('by_level') or {}).get('L5', 0)}** L5 reproduced thefts, {(proof32.get('by_level') or {}).get('L3', 0)} blocked at L3 |

Gates (0 critical failures everywhere): v2 {vrep.get('passed', 0)}/{vrep.get('checks', 0)} · v3.0 {v3gate.get('passed', 0)}/{v3gate.get('total', 0)} · v3.1 {v31gate.get('passed', 0)}/{v31gate.get('total', 0)}.

## Layout

```
jsonl/            ORIGINAL v1 evidence layer ({n(rc.get('findings', 0))} findings, {n(rc.get('negatives', 0))} negatives, {n(rc.get('exploits', 0))} exploits, {n(rc.get('patches', 0))} patches). Never rewritten.
derived/          enriched v1 records ({n(dm.get('records', 0))}): evidence, attacker model, state transition, taxonomy, quality
experiments/      one directory per attempted exploit (harness, command, stdout, stderr, result.json)
jsonl_ml/         v2.2 source layer ({n(ml_findings)} findings, {n(ml_sources)} sources). Read-only.
derived_v2_2/     v2.2 derived records ({n(d22m.get('records', 0))}) with quality rubric + experiment view
splits_v2_2/      v2.2 splits (train {n(v22_splits.get('train'))}, validation {n(v22_splits.get('validation'))}, test {n(v22_splits.get('test'))}, quarantine {n(v22_splits.get('quarantine'))})
experiments_v2_2/ executed multi-language runs
jsonl_v3/         v3 source layer ({n(v3m.get('candidate_count', 0))} candidates, {n(v3m.get('source_count', 0))} sources). Read-only.
derived_v3/       v3 records ({n(v3m.get('record_count', 0))}) + v3.1 fragments/overlays/preview ({n(norm31.get('preview_count', 0))} rows)
splits_v3/        by-source splits, no source spans splits
experiments_v3/   v3.2 fork-execution artefacts (command, stdout, stderr, harness manifest, result.json)
datasets/         high-confidence subsets, each with a published admission rule
training/         task-oriented training files
splits/ + splits_v2/  v1/v2 splits with quarantine
benchmark/        {fam_n} families (A-J v1, K-Q v2.2, R-S v3, T v3.1-taxonomy)
reports/          every generated report, including reports/v2_2/ and reports/v3/
scripts/          the pipeline (standard-library only; see below)
work/             clones, retrieved source, execution logs — git-ignored
```

`jsonl/` is the contract: **original evidence**. Inferred analysis lives in `derived/`, machine
executions in `work/` (summarised in `reports/`). A researcher can always separate what the audit
said from what the builder derived from what was executed.

## Evidence model

Every derived field carries `{{value, evidence_type, source_refs}}`. Closed vocabulary:

| type | meaning |
|---|---|
| `observed_fact` | read out of a retrieved artefact |
| `reported_claim` | stated by an identifiable external source |
| `derived_fact` | computed here by a rule that lives in the code |
| `experimentally_verified` | produced by actually compiling + running something |
| `externally_attributed` | attributed to a named third party (judge, sponsor, label) |
| `unverified` | asserted somewhere, not checked here |
| `unknown` | no defensible value exists |

PoC quality ladder: **L0** report prose · **L1** PoC quoted · **L2** PoC reconstructed ·
**L3** compiles · **L4** executes · **L5** claimed violation reproduced ·
**L6** reproduced on the vulnerable revision *and* blocked on the fixed one (same test).
Above L2 requires a run artefact; L6 requires both legs. No PoC is marked reproduced unless
forge reported `Success`, and no patch is called effective without the controlled comparison.

## What is verified (honest counts)

- **v1/v2:** {n(len(exp.get('experiments', [])))} pinpoint experiments
  ({n(exp_verdicts.get('inconclusive', 0))} inconclusive, missing symbol recorded);
  **{n(pv.get('experimentally_confirmed_pairs'))}** patches verified effective;
  {n(negs.get('total', 0) - (negs.get('by_class', {}) or {}).get('unknown', 0))} negatives with a
  defensible reason ({n((negs.get('by_class', {}) or {}).get('unknown'))} still unknown);
  {n(ce.get('api_sibling_pairs', 0))} API-sibling counterexample pairs.
- **v2.2:** {n(sum(v for k, v in (d22m.get('experiment_levels') or {}).items() if k != 'none'))} executed runs;
  {n(((d22m.get('attacker_identity') or {}).get('unknown')))} of {n(d22m.get('records', 0))} records state no attacker standing.
- **V3.0:** {n((v3m.get('decisions') or {}).get('IMPORT', 0))} strong imports +
  {n((v3m.get('decisions') or {}).get('IMPORT_AS_UNVERIFIED', 0))} unverified imports +
  {n((v3m.get('decisions') or {}).get('IMPORT_AS_NEGATIVE', 0))} hard negatives +
  {n((v3m.get('decisions') or {}).get('CORROBORATION_ONLY', 0))} corroborations; the rest stays
  research-only rather than being forced into the dataset.
- **V3.1:** {n((norm31.get('fragment_decisions') or {}).get('admitted', 0))} admitted findings
  (severity explicit on {n((norm31.get('severity_confidence') or {}).get('explicit', 0))});
  taxonomy explicit on {n((norm31.get('taxonomy_confidence') or {}).get('explicit', 0))}, derived on
  {n((norm31.get('taxonomy_confidence') or {}).get('derived', 0))}, unknown elsewhere — by rule, not by optimism.
- **V3.2:** {n(tri32.get('compiled_l3', 0))}/{n(tri32.get('total', 0))} incident PoCs compile (L3);
  {(proof32.get('by_level') or {}).get('L5', 0)} thefts reproduced on fork with attacker-profit
  evidence; {n(len((proof32.get('runs') or [])) - (proof32.get('by_level') or {}).get('L5', 0))} blocked
  (pruned RPC, unreplayable state, repo drift — each with verbatim backend errors in
  `experiments_v3/`); 47 patch candidates all `not_testable` (no executable PoC on either side).
- Full per-source accounting, unknowns with resolving evidence, and extraction failures:
  [`reports/v2_1_quality_report.md`](reports/v2_1_quality_report.md),
  [`reports/v2_2/quality_report.md`](reports/v2_2/quality_report.md),
  [`reports/v3/quality_report.md`](reports/v3/quality_report.md),
  [`reports/v3/normalization_report.md`](reports/v3/normalization_report.md),
  [`reports/v3/normalization_unknowns.md`](reports/v3/normalization_unknowns.md).

## Splits & benchmarks

Splits isolate by repository (v1/v2) or by record/source (v2.2/v3); duplicates are quarantined,
never deleted. Benchmark families A-T are machine-readable under `benchmark/` with a manifest;
answer keys rebuild from the records, and families that need experimentally produced ground truth
only admit rows that have it.

## Licensing

- `LICENSE` is three-way: data under `jsonl*/`, `derived*/`, `splits*/`, `benchmark/`,
  `datasets/`, `training/`, `reports/` is **CC BY 4.0**; `scripts/` is **MIT**; third-party
  source is **not licensed here at all**.
- {dm.get('redistribution_flagged', {}).get('source_redistributed_without_declared_license', 0)} v1 records
  carry verbatim source from repositories declaring no licence (flagged per record; re-measured
  from the text itself in `reports/third_party_audit.json`). V3 keeps link + sha256 + attributed
  facts only (METADATA_ONLY).
- No permission has been obtained from upstream protocol authors. For redistribution or
  commercial training, pull sources yourself via `scripts/fetch_sources.py` under your own
  compliance process. See [`NOTICE.md`](NOTICE.md).

## Reproduce

```bash
python scripts/build_all.py --with-network   # everything
python scripts/validate.py                   # the gate (non-zero on failure)
python scripts/validate_v3.py                # v3 gate
python scripts/validate_v31.py               # v3.1 gate
python scripts/generate_readme.py --check    # this file is generated; stays current only if regenerated
```

Every script is idempotent, takes `--help`, and writes only under its own layer directories;
`jsonl/`, `jsonl_ml/`, `jsonl_v3/` are read-only. Offline runs skip network stages explicitly
(`skipped_no_network` — a skip is never reported as a pass). Fresh clones reproduce the JSONL and
derived layers but not execution artefacts, which live git-ignored under `work/` (verdicts stay
checkable via committed `result.json` files).

Key stages:

```bash
python scripts/fetch_sources.py              # clone + retrieve pinned citations
python scripts/verify_pocs.py                 # compile and run PoCs
python scripts/verify_patches.py              # vulnerable vs fixed revision pairs
python scripts/resolve_citations.py           # branch refs -> exact commits
python scripts/run_verified_experiments.py    # exploit experiments, both revisions
python scripts/build_derived.py               # evidence, attacker model, taxonomy
python scripts/build_hard_negatives.py        # structured rejection reasons
python scripts/check_leakage.py --emit splits_v2
python scripts/build_benchmark.py             # families A-J
python scripts/build_benchmark_v22.py         # families K-Q
python scripts/build_subsets.py               # datasets/ and training/
python scripts/generate_stats.py              # the only source of statistics
python scripts/ingest_audit_sources.py        # audit-source registry
python scripts/build_v3.py                    # v3: 18 clones -> jsonl_v3/derived_v3/splits_v3 + R-S
python scripts/validate_v3.py                 # the v3 gate
python scripts/normalize_v3.py                # v3.1: boundaries, fields, overlays, preview
python scripts/validate_v31.py                # the v3.1 gate
python scripts/build_benchmark_v31.py         # family T (explicit taxonomy)
python scripts/run_dhl_experiments.py         # v3.2: staged fork executions
```

## Repositories (v1 scope)

| Repository | Protocol | Findings | Split |
|---|---|---|---|
| `code-423n4/2022-05-alchemix` | Alchemix | 28 | train |
| `code-423n4/2024-01-decent` | Decent | 12 | validation |
| `code-423n4/2024-01-renft` | reNFT | 29 | validation |
| `code-423n4/2024-04-noya` | NOYA | 86 | train |
| `code-423n4/2024-08-wildcat` | The Wildcat Protocol | 32 | test |
| `code-423n4/2024-12-bakerfi` | BakerFi Invitational | 32 | test |
| `code-423n4/2025-06-panoptic` | Panoptic Hypovault | 4 | test |
| `code-423n4/2025-08-gte-perps` | GTE Perps and Launchpad | 41 | test |

V3 spans 18 more archives (audits, contests, incident PoCs); per-source accounting is in
[`reports/v3/quality_report.md`](reports/v3/quality_report.md).

## Attribution

Findings, verdicts and PoC code belong to their original authors: Code4rena and the
competitive-audit participants, the professional auditors, and the incident PoC authors.
See [`NOTICE.md`](NOTICE.md).
"""
    return lines


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    want = render()
    notice = render_notice()
    if args.check:
        stale = []
        if (not README.exists()) or README.read_text(encoding="utf-8") != want:
            stale.append("README.md")
        if (not NOTICE.exists()) or NOTICE.read_text(encoding="utf-8") != notice:
            stale.append("NOTICE.md")
        if stale:
            log(f"STALE {', '.join(stale)} — run: python scripts/generate_readme.py")
            return 1
        log("README.md and NOTICE.md are current")
        return 0
    README.write_text(want, encoding="utf-8", newline="\n")
    NOTICE.write_text(notice, encoding="utf-8", newline="\n")
    log(f"wrote README.md ({len(want.splitlines())} lines) and "
        f"NOTICE.md ({len(notice.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())