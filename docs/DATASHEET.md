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
- V3.0: 5,467 admitted of 7,712 candidates across 18 sources; levels {"L0": 4586, "L1": 754, "L3": 125, "L5": 2}.
- Vbeta (isolated): 6,935 admitted of 7,060 candidates across 15 sources; levels {"L0": 6981, "L1": 79}.
- Benchmark: 19,631 exactly-scorable tasks (majority micro-accuracy 0.8736). 864 further tasks across 3 families are excluded from exact match because they are generative, judge-graded or descriptive (`docs/RUBRIC.md`); the exclusion is recorded per family, never silent.
- Field coverage: 11 of 28 tracked fields under 50% known (see `reports/field_coverage.md`). `unknown` is a counted outcome everywhere.

## Collection process

- v1: Code4rena audit repositories + dependency repos + code4rena.com reports; citations resolved to commits (`scripts/resolve_citations.py`).
- v2.2: advisories, audits, bounties, post-mortems across five languages.
- V3: 18 cloned archives (audits, contests, incident PoCs, one research dataset); provenance is clone-HEAD + file sha256.
- Vbeta: first-party audit pages observed live (URL + titles + date receipts) plus a Solodit HIGH+MEDIUM mirror (auditor originals canonical); PDFs mined in temp space and deleted (METADATA_ONLY).

## Preprocessing, cleaning, labeling

- Admission computed in code (`decide()`): IMPORT only on title + severity + link + status all observed; near-duplicates quarantined as CORROBORATION_ONLY with links, never deleted; splits isolate by repository/source with quarantine files.
- Taxonomy assigned only where evidence supports it (`unknown` otherwise); severities preserved verbatim; team-reported `Fixed` never promoted to `verified_patch`.
- Splits: no source spans splits (machine-checked); duplicates quarantined, never deleted.

## Uses

- Past uses: vulnerability detection/reasoning benchmarks (families A–V), exploit-verification and patch-verification studies on executed subsets.
- Intended: training and evaluating security-reasoning models with honest abstention (`unknown`, `unlabeled`, quarantine).
- Out of scope: production audit decisions; L0/L1 rows are not executable proof; saturated families (majority >= 0.94, see `docs/RUBRIC.md`) carry no signal.

## Distribution

- Data layers (`jsonl*/`, `derived*/`, `splits*/`, `benchmark/`, `datasets/`, `training/`, `reports/`): CC BY 4.0. `scripts/`: MIT. Third-party source: not licensed here at all (see `NOTICE.md`).
- 424 v1 records carry verbatim source from repositories declaring no licence (flagged per record). For strictly licence-clean use, resolve `code_context[].snippet` entries from the original audits.

## Maintenance

- Maintained via `scripts/build_all.py` stages with `scripts/run_gates.py` (26 gates) as the release bar; README, stats and field coverage regenerate from artefacts (`--check` enforced in CI).
- Contact/limitations: validation reports record every unknown, exclusion and failure reason; limitations are published in `reports/benchmark_metrics.md` and `reports/reproducibility_report.md`, not hidden.
