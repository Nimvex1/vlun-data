# VLUN — smart-contract security reasoning dataset

A provenance-preserving corpus of smart-contract security findings. Every record traces to a
public artefact — a report section, a submission issue, a registry payload, or a commit-pinned
permalink — and every claim carries its evidence type. Governing rule: truth over scale;
`unknown` is a counted outcome, never a gap to fill by guessing.

## Dataset at a glance

| Layer | Source | Records | Strongest evidence |
|---|---|---|---|
| v1 | 8 Code4rena audits (Solidity) | 722 derived | 9 pinpoint experiments, **7** L6 verified patches |
| v2.2 | advisories/audits/bounties/post-mortems, 5 languages | 137 | 37 executed runs, levels `{'L3': 1, 'L5': 35, 'L6': 1, 'none': 100}` |
| V3.0 | 18 new archives (audits, contests, incident PoCs, 1 research dataset) | 5,467 admitted / 7,712 candidates | L0/L1 only — nothing executed in this pass |
| V3.1 | normalized findings with spans + overlays | 12,504 preview rows (7,037 new) | severity on 11,610, class on 2,093, files on 5,790 |
| V3.2 | fork executions of incident PoCs | 6 runs | **2** L5 reproduced thefts, 4 blocked at L3 |

Gates (0 critical failures everywhere): v2 71/71 · v3.0 33/33 · v3.1 32/32.

## Layout

```
jsonl/            ORIGINAL v1 evidence layer (264 findings, 458 negatives, 155 exploits, 38 patches). Never rewritten.
derived/          enriched v1 records (722): evidence, attacker model, state transition, taxonomy, quality
experiments/      one directory per attempted exploit (harness, command, stdout, stderr, result.json)
jsonl_ml/         v2.2 source layer (137 findings, 112 sources). Read-only.
derived_v2_2/     v2.2 derived records (137) with quality rubric + experiment view
splits_v2_2/      v2.2 splits (train 76, validation 30, test 31, quarantine 2)
experiments_v2_2/ executed multi-language runs
jsonl_v3/         v3 source layer (7,712 candidates, 18 sources). Read-only.
derived_v3/       v3 records (5,467) + v3.1 fragments/overlays/preview (12,504 rows)
splits_v3/        by-source splits, no source spans splits
experiments_v3/   v3.2 fork-execution artefacts (command, stdout, stderr, harness manifest, result.json)
datasets/         high-confidence subsets, each with a published admission rule
training/         task-oriented training files
splits/ + splits_v2/  v1/v2 splits with quarantine
benchmark/        17 families (A-J v1, K-Q v2.2, R-S v3, T v3.1-taxonomy)
reports/          every generated report, including reports/v2_2/ and reports/v3/
scripts/          the pipeline (standard-library only; see below)
work/             clones, retrieved source, execution logs — git-ignored
```

`jsonl/` is the contract: **original evidence**. Inferred analysis lives in `derived/`, machine
executions in `work/` (summarised in `reports/`). A researcher can always separate what the audit
said from what the builder derived from what was executed.

## Evidence model

Every derived field carries `{value, evidence_type, source_refs}`. Closed vocabulary:

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

- **v1/v2:** 9 pinpoint experiments
  (2 inconclusive, missing symbol recorded);
  **7** patches verified effective;
  331 negatives with a
  defensible reason (127 still unknown);
  71 API-sibling counterexample pairs.
- **v2.2:** 37 executed runs;
  123 of 137 records state no attacker standing.
- **V3.0:** 3,517 strong imports +
  1,934 unverified imports +
  16 hard negatives +
  108 corroborations; the rest stays
  research-only rather than being forced into the dataset.
- **V3.1:** 7,037 admitted findings
  (severity explicit on 4,231);
  taxonomy explicit on 596, derived on
  1,497, unknown elsewhere — by rule, not by optimism.
- **V3.2:** 127/129 incident PoCs compile (L3);
  2 thefts reproduced on fork with attacker-profit
  evidence; 4 blocked
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
- 424 v1 records
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
