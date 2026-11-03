# Datasheet for VLUN

## Motivation

VLUN exists to give model builders a vulnerability corpus where every claim
carries its evidence type and every count recomputes from the files. It was
created because public audit findings are scattered across contest repos,
PDFs and aggregators with no common schema, no splits, and no executable
ground truth. Governing rule: truth over scale.

## Composition

- v1 (immutable): 264 findings, 458 negatives, 155 exploits, 38 patches, 8 protocol rows, 11 metadata rows, 19 error rows.
- v2.2 (five languages): 137 derived records.
- V3.0: 5,467 admitted of 7,712 candidates across 18 sources; levels {"L0": 4586, "L1": 754, "L3": 115, "L4": 7, "L5": 5}.
- Vbeta (isolated): 6,935 admitted of 7,060 candidates across 15 sources; levels {"L0": 6981, "L1": 79}.
- Benchmark: the primary metric covers 720 exactly-scorable rows of the PRIMARY set (1 family: A_vulnerability_detection.jsonl); the train-only majority floor on the 147 held-out test rows is 0.5510 (macro-F1 0.3553). The family status is computed at run time from the independent audit's measurements, not from a list: 32 rows sit in EXPLORATORY families (demoted: too few rows, a holdout too small to estimate on, or a single observed label), 18,911 rows in INVALID families (a validity flag makes them unusable as evaluation evidence), 2,486 in retired families (retirement is a location, not a verdict) and 1,876 in families with no exactly-matchable key — the exclusion is recorded per family, never silent. The continuity twin covers all 22,149 scorable rows ever shipped. **The benchmark is OPEN-KEY**: every benchmark family row carries its answer key in the same file as its input; the key is committed, so every family is OPEN-KEY and no family may be described as hidden or protected against repository-level leakage. The only protected evaluation in this project is the VLUN-Prove private split, whose answer key lives outside the tracked tree and is committed to by hash (2 files).
- Field coverage: 11 of 28 tracked fields under 50% known (see `reports/field_coverage.md`). `unknown` is a counted outcome everywhere.

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

- Maintained via `scripts/build_all.py` stages with `scripts/run_gates.py` (53 gates) as the release bar; README, stats and field coverage regenerate from artefacts (`--check` enforced in CI).
- Contact/limitations: validation reports record every unknown, exclusion and failure reason; limitations are published in `reports/benchmark_metrics.md` and `reports/reproducibility_report.md`, not hidden.
