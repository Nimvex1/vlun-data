# VLUN Audit — Executive Summary

> Generated as the final reconciliation artifact for the metadata-vs-trainable audit.
> All figures are derived directly from `reports/metadata_vs_trainable_audit.json`
> and independently re-checked by `scripts/verify_audit.py`.

## 1. Final verifier status

**ALL CHECKS PASS** — no exceptions.

- Checks run: **1156**, passed: **1156**, failed: **0**
- Discrepancies: **none**
- Full log: `reports/audit_verification.txt`

One verifier bug was found and fixed during this pass (no dataset or audit-data change):
check **4a (`coverage_pct` range)** incorrectly treated `coverage_pct` as a single scalar
number, when the audit stores it as an object of six sub-percentages
(`pct_code`, `pct_diff`, `pct_poc`, `pct_prose`, `pct_spec`, `pct_metadata_flagged`).
The check was corrected in `scripts/verify_audit.py` to validate every numeric
sub-value of each `coverage_pct` object against `[0.0, 100.0]`. It now validates
1,134 sub-percentage values across 189 objects — all in range. The audit data
itself was correct; no rebuild was required.

## 2. Bucket totals and percentages

Total rows audited: **268,776** across **189** files.

| Bucket | Rows | % of total |
|---|---:|---:|
| FULLY_TRAINABLE | 32,744 | 12.18% |
| PARTIAL_TEXT_NO_CODE | 87,939 | 32.72% |
| METADATA_ONLY_STUB | 148,093 | 55.10% |
| **TOTAL** | **268,776** | **100.00%** |

Hydration-source row totals: HYDRATABLE_FROM_LOCAL_WORK =
75,059,
HYDRATABLE_FROM_GIT_OR_GITHUB =
81,708,
UNHYDRATABLE_DEAD_POINTER =
112,009. Invalid lines: 0.

## 3. Compact per-layer summary

`Stub` = METADATA_ONLY_STUB rows; `Fully` / `Partial` = bucket row counts.
"Dominant hydration source" is the most common per-file dominant source in that layer.

| Layer | Files | Rows | Fully | Partial | Stub | Dominant hydration source |
|---|---:|---:|---:|---:|---:|---|
| benchmark | 34 | 24,078 | 5,513 | 5,777 | 12,788 | UNHYDRATABLE_DEAD_POINTER |
| datasets | 3 | 314 | 6 | 308 | 0 | HYDRATABLE_FROM_GIT_OR_GITHUB |
| other/annotation | 1 | 301 | 194 | 75 | 32 | UNHYDRATABLE_DEAD_POINTER |
| other/derived | 3 | 561 | 324 | 218 | 19 | HYDRATABLE_FROM_GIT_OR_GITHUB |
| other/derived_poc_queue | 1 | 1,046 | 127 | 28 | 891 | UNHYDRATABLE_DEAD_POINTER |
| other/derived_rejections | 1 | 458 | 5 | 453 | 0 | HYDRATABLE_FROM_GIT_OR_GITHUB |
| other/derived_siblings | 3 | 458 | 62 | 396 | 0 | HYDRATABLE_FROM_LOCAL_WORK |
| other/derived_span_tasks | 2 | 25,008 | 12,504 | 0 | 12,504 | HYDRATABLE_FROM_LOCAL_WORK |
| other/derived_v2_2 | 3 | 169 | 46 | 102 | 21 | HYDRATABLE_FROM_GIT_OR_GITHUB |
| other/experiments | 1 | 155 | 0 | 0 | 155 | UNHYDRATABLE_DEAD_POINTER |
| other/nextdata | 4 | 1,427 | 1,350 | 77 | 0 | UNHYDRATABLE_DEAD_POINTER |
| other/reports | 1 | 56 | 7 | 39 | 10 | HYDRATABLE_FROM_GIT_OR_GITHUB |
| other/splits_v2 | 4 | 945 | 496 | 55 | 394 | HYDRATABLE_FROM_GIT_OR_GITHUB |
| other/splits_v2_2 | 4 | 1,082 | 2 | 1,080 | 0 | UNHYDRATABLE_DEAD_POINTER |
| other/splits_v3 | 1 | 0 | 0 | 0 | 0 | NONE |
| other/tests | 29 | 275 | 196 | 58 | 21 | UNHYDRATABLE_DEAD_POINTER |
| other/training | 10 | 16,129 | 3,650 | 12,032 | 447 | UNHYDRATABLE_DEAD_POINTER |
| prove | 1 | 210 | 46 | 135 | 29 | HYDRATABLE_FROM_GIT_OR_GITHUB |
| taxonomy | 2 | 449 | 42 | 251 | 156 | UNHYDRATABLE_DEAD_POINTER |
| v1 | 9 | 1,877 | 928 | 267 | 682 | HYDRATABLE_FROM_GIT_OR_GITHUB |
| v2.2 | 10 | 249 | 135 | 114 | 0 | HYDRATABLE_FROM_GIT_OR_GITHUB |
| v3 | 12 | 72,612 | 1,105 | 36,141 | 35,366 | HYDRATABLE_FROM_LOCAL_WORK |
| v4 | 14 | 46,597 | 1 | 11,908 | 34,688 | HYDRATABLE_FROM_GIT_OR_GITHUB |
| vbeta | 11 | 34,370 | 1,630 | 12,540 | 20,200 | UNHYDRATABLE_DEAD_POINTER |
| wave1 | 25 | 39,950 | 4,375 | 5,885 | 29,690 | HYDRATABLE_FROM_GIT_OR_GITHUB |

## 4. Required layer groups — stub-file coverage

All 6 required layer groups are covered by the hydration plan. For each group the
number of stub-file sections and 2 example paths are shown below. Every section in
these groups contains (verified programmatically): a **raw sample record** (a
`Sample stub record` JSON block), a **"What is missing inline"** bullet list, and
**"Exact hydration steps"**.

| Layer group | Audit layer | Stub-file sections | 2 example paths |
|---|---|---:|---|
| wave1/ | `wave1` | 24 | `wave1/00_governance/rights.jsonl`; `wave1/00_governance/source_registry.jsonl` |
| jsonl_v3/ (V3) | `v3` | 11 | `derived_v3/candidate_ledger.jsonl`; `derived_v3/corroborations.jsonl` |
| Vbeta/ | `vbeta` | 10 | `Vbeta/benchmark_vbeta/vbeta_U_language_routing.jsonl`; `Vbeta/benchmark_vbeta/vbeta_V_source_tier_routing.jsonl` |
| jsonl_ml/ (v2.2) | `v2.2` | 8 | `jsonl_ml/findings_cairo.jsonl`; `jsonl_ml/findings_move.jsonl` |
| jsonl_v4/ / derived_v4/ / distribution_v1/ (V4) | `v4` | 12 | `derived_v4/admitted_ledger.jsonl`; `derived_v4/candidate_ledger.jsonl` |
| v1 (derived/, jsonl/, datasets/) | `v1` | 9 | `datasets/verified_negatives.jsonl`; `derived/records.jsonl` |

Coverage cross-check by path prefix: wave1/ = 24; Vbeta/ = 10;
jsonl_v3/ (2) + derived_v3/ (9) = V3 11; jsonl_ml/ = v2.2 8
(note: derived_v2_2/ and splits_v2_2/ are separate `other/*` layers, not v2.2);
jsonl_v4/ (2) + derived_v4/ (3) + distribution_v1/ (7) = V4 12;
v1 jsonl/ (7) + derived/ (1) + datasets/ (1) = v1 9.

## 5. No dataset file modified

`git status --short` shows no modification to any `.jsonl` or dataset `.json` file.
The only tracked modifications are two pre-existing wave1 Python tooling scripts
(not dataset files, not part of this audit's edits); all other entries are new,
untracked report/script files produced by the audit.

```
 M wave1/scripts/assign_group_splits.py
 M wave1/scripts/validate_wave1.py
?? reports/_audit_explore_prove_wave1_misc.md
?? reports/_audit_explore_v1.md
?? reports/_audit_explore_v22_v3.md
?? reports/_audit_explore_vbeta_v4.md
?? reports/audit_verification.txt
?? reports/metadata_stub_hydration_plan.md
?? reports/metadata_vs_trainable_audit.json
?? reports/metadata_vs_trainable_audit.md
?? scripts/audit_trainable_vs_metadata.py
?? scripts/verify_audit.py
```

## 6. Full 189-row Markdown table (verbatim from `reports/metadata_vs_trainable_audit.md`)

Header: `| File | Layer | Total Rows | Fully Trainable | Partial (Text Only) | Metadata Stub | % Code | % Diff | % PoC | % Prose | Hydration Source |`

| File | Layer | Total Rows | Fully Trainable | Partial (Text Only) | Metadata Stub | % Code | % Diff | % PoC | % Prose | Hydration Source |
|---|---|---|---|---|---|---|---|---|---|---|
| Vbeta/benchmark_vbeta/vbeta_U_language_routing.jsonl | vbeta | 6219 | 57 | 1572 | 4590 | 1.2 | 0.0 | 0.1 | 25.8 | DEAD(6162) |
| Vbeta/benchmark_vbeta/vbeta_V_source_tier_routing.jsonl | vbeta | 6935 | 60 | 1917 | 4958 | 1.2 | 0.0 | 0.1 | 28.2 | DEAD(6875) |
| Vbeta/derived_vbeta/candidate_ledger.jsonl | vbeta | 7060 | 64 | 1955 | 5041 | 1.2 | 0.0 | 0.1 | 28.2 | GIT(6229)/DEAD(767) |
| Vbeta/derived_vbeta/corroborations.jsonl | vbeta | 0 | 0 | 0 | 0 | 0.0 | 0.0 | 0.0 | 0.0 | NONE |
| Vbeta/derived_vbeta/duplicates.jsonl | vbeta | 63 | 0 | 60 | 3 | 0.0 | 0.0 | 0.0 | 95.2 | DEAD(63) |
| Vbeta/derived_vbeta/negatives.jsonl | vbeta | 5 | 0 | 5 | 0 | 0.0 | 0.0 | 0.0 | 100.0 | DEAD(4)/GIT(1) |
| Vbeta/derived_vbeta/records.jsonl | vbeta | 6935 | 1381 | 5016 | 538 | 20.0 | 0.1 | 0.2 | 92.2 | DEAD(3309)/GIT(2245) |
| Vbeta/fetched/receipts.jsonl | vbeta | 15 | 0 | 7 | 8 | 0.0 | 0.0 | 0.0 | 46.7 | GIT(7)/DEAD(5)/LOCAL(3) |
| Vbeta/jsonl_vbeta/findings.jsonl | vbeta | 7060 | 64 | 1955 | 5041 | 1.2 | 0.0 | 0.1 | 28.2 | DEAD(4994)/GIT(2002) |
| Vbeta/jsonl_vbeta/sources.jsonl | vbeta | 15 | 0 | 0 | 15 | 0.0 | 0.0 | 0.0 | 0.0 | GIT(10)/DEAD(5) |
| Vbeta/splits_vbeta/quarantine.jsonl | vbeta | 63 | 4 | 53 | 6 | 6.3 | 0.0 | 0.0 | 90.5 | DEAD(59) |
| annotation/iaa_v1/sample.jsonl | other/annotation | 301 | 194 | 75 | 32 | 64.8 | 1.3 | 3.0 | 89.0 | DEAD(95)/GIT(12) |
| benchmark/A_vulnerability_detection.jsonl | benchmark | 720 | 425 | 295 | 0 | 59.0 | 0.0 | 1.0 | 100.0 | DEAD(293)/GIT(2) |
| benchmark/C_attacker_reasoning.jsonl | benchmark | 720 | 433 | 287 | 0 | 60.1 | 0.0 | 1.2 | 100.0 | DEAD(285)/GIT(2) |
| benchmark/D_exploit_construction.jsonl | benchmark | 720 | 566 | 41 | 113 | 79.6 | 0.0 | 13.9 | 83.3 | DEAD(148)/GIT(6) |
| benchmark/F_false_positive_rejection.jsonl | benchmark | 458 | 318 | 140 | 0 | 69.4 | 0.0 | 0.4 | 100.0 | DEAD(139)/GIT(1) |
| benchmark/Fa_rejection_evidence_axis_vector.jsonl | benchmark | 458 | 458 | 0 | 0 | 100.0 | 0.0 | 0.7 | 100.0 | NONE |
| benchmark/Fb_duplicate_radar_pair.jsonl | benchmark | 552 | 552 | 0 | 0 | 100.0 | 0.0 | 1.1 | 100.0 | NONE |
| benchmark/G_patch_verification.jsonl | benchmark | 38 | 38 | 0 | 0 | 100.0 | 0.0 | 0.0 | 100.0 | NONE |
| benchmark/H_verified_exploit.jsonl | benchmark | 7 | 7 | 0 | 0 | 100.0 | 0.0 | 42.9 | 100.0 | NONE |
| benchmark/I_verified_non_exploit.jsonl | benchmark | 3 | 0 | 3 | 0 | 0.0 | 0.0 | 0.0 | 100.0 | DEAD(3) |
| benchmark/J_verified_patch.jsonl | benchmark | 7 | 3 | 4 | 0 | 100.0 | 0.0 | 42.9 | 42.9 | GIT(4) |
| benchmark/Q_evidence_type_and_quality_rubric.jsonl | benchmark | 137 | 137 | 0 | 0 | 100.0 | 24.8 | 20.4 | 100.0 | NONE |
| benchmark/independent/canonical_holdout/detection.heldout.part-000.jsonl | benchmark | 90 | 8 | 33 | 49 | 8.9 | 0.0 | 0.0 | 44.4 | DEAD(65)/LOCAL(15)/GIT(2) |
| benchmark/independent/canonical_holdout/language.heldout.part-000.jsonl | benchmark | 2048 | 230 | 1719 | 99 | 11.2 | 0.0 | 1.1 | 95.2 | GIT(1517)/LOCAL(267)/DEAD(34) |
| benchmark/independent/canonical_holdout/severity.heldout.part-000.jsonl | benchmark | 2766 | 350 | 2298 | 118 | 12.7 | 0.0 | 0.8 | 95.7 | GIT(2109)/LOCAL(252)/DEAD(55) |
| benchmark/independent/secondary_holdout_exploratory_keys.jsonl | benchmark | 32 | 0 | 0 | 32 | 0.0 | 0.0 | 0.0 | 0.0 | DEAD(24)/GIT(8) |
| benchmark/independent/secondary_holdout_exploratory_tasks.jsonl | benchmark | 32 | 32 | 0 | 0 | 100.0 | 0.0 | 12.5 | 100.0 | NONE |
| benchmark/independent/secondary_holdout_keys.jsonl | benchmark | 2684 | 0 | 2 | 2682 | 0.0 | 0.0 | 0.0 | 0.1 | DEAD(2629)/GIT(55) |
| benchmark/independent/secondary_holdout_tasks.jsonl | benchmark | 2684 | 146 | 307 | 2231 | 5.7 | 0.0 | 0.2 | 16.7 | DEAD(2538) |
| benchmark/independent/v1_task_holdout/attacker_reasoning.jsonl | benchmark | 257 | 3 | 64 | 190 | 1.9 | 0.0 | 0.0 | 24.9 | DEAD(254) |
| benchmark/independent/v1_task_holdout/exploit_reasoning.jsonl | benchmark | 5 | 0 | 1 | 4 | 0.0 | 0.0 | 0.0 | 20.0 | GIT(5) |
| benchmark/independent/v1_task_holdout/negative_reasoning.jsonl | benchmark | 106 | 0 | 0 | 106 | 0.0 | 0.0 | 0.0 | 0.0 | DEAD(106) |
| benchmark/independent/v1_task_holdout/patch_reasoning.jsonl | benchmark | 7 | 0 | 0 | 7 | 0.0 | 0.0 | 0.0 | 0.0 | GIT(7) |
| benchmark/independent/v1_task_holdout/vulnerability_detection.jsonl | benchmark | 257 | 18 | 62 | 177 | 8.2 | 0.0 | 0.0 | 29.6 | DEAD(237)/GIT(2) |
| benchmark/retired_families/B_root_cause_reasoning.jsonl | benchmark | 720 | 720 | 0 | 0 | 100.0 | 0.0 | 1.4 | 100.0 | NONE |
| benchmark/retired_families/E_exploit_verification.jsonl | benchmark | 720 | 328 | 14 | 378 | 46.7 | 0.0 | 9.9 | 46.4 | DEAD(387)/GIT(5) |
| benchmark/retired_families/K_language_ecosystem_routing.jsonl | benchmark | 137 | 137 | 0 | 0 | 100.0 | 24.8 | 20.4 | 100.0 | NONE |
| benchmark/retired_families/L_severity_reconciliation.jsonl | benchmark | 137 | 137 | 0 | 0 | 100.0 | 24.8 | 19.7 | 100.0 | NONE |
| benchmark/retired_families/M_experiment_level_classification.jsonl | benchmark | 37 | 37 | 0 | 0 | 100.0 | 62.2 | 13.5 | 100.0 | NONE |
| benchmark/retired_families/N_attacker_identity_extraction.jsonl | benchmark | 137 | 137 | 0 | 0 | 100.0 | 24.8 | 19.7 | 100.0 | NONE |
| benchmark/retired_families/O_record_class_and_scope.jsonl | benchmark | 137 | 137 | 0 | 0 | 100.0 | 24.8 | 20.4 | 100.0 | NONE |
| benchmark/retired_families/P_provenance_tier_and_rights.jsonl | benchmark | 137 | 137 | 0 | 0 | 100.0 | 0.0 | 0.0 | 100.0 | NONE |
| benchmark/retired_families/v3_S_contest_outcome.jsonl | benchmark | 1072 | 9 | 230 | 833 | 1.2 | 0.0 | 0.0 | 21.9 | DEAD(1063) |
| benchmark/retired_families/v3_T_taxonomy_explicit.jsonl | benchmark | 589 | 1 | 13 | 575 | 0.3 | 0.0 | 0.0 | 2.2 | DEAD(588) |
| benchmark/v3_R_source_tier_routing.jsonl | benchmark | 5467 | 9 | 264 | 5194 | 0.3 | 0.0 | 0.0 | 4.8 | DEAD(5458) |
| datasets/verified_exploits.jsonl | datasets | 5 | 0 | 5 | 0 | 0.0 | 0.0 | 0.0 | 100.0 | GIT(5) |
| datasets/verified_findings.jsonl | datasets | 302 | 6 | 296 | 0 | 2.0 | 0.0 | 0.0 | 100.0 | GIT(296) |
| datasets/verified_negatives.jsonl | v1 | 202 | 0 | 202 | 0 | 0.0 | 0.0 | 0.5 | 100.0 | GIT(202) |
| datasets/verified_patches.jsonl | datasets | 7 | 0 | 7 | 0 | 0.0 | 0.0 | 0.0 | 100.0 | GIT(7) |
| derived/counterexamples.jsonl | other/derived | 63 | 3 | 42 | 18 | 4.8 | 0.0 | 0.0 | 69.8 | GIT(60) |
| derived/hard_negatives.jsonl | other/derived | 458 | 318 | 140 | 0 | 69.4 | 0.2 | 0.7 | 100.0 | GIT(140) |
| derived/records.jsonl | v1 | 722 | 434 | 0 | 288 | 100.0 | 1.8 | 14.5 | 100.0 | GIT(288) |
| derived/root_cause_candidates.jsonl | other/derived | 40 | 3 | 36 | 1 | 7.5 | 0.0 | 0.0 | 95.0 | DEAD(37) |
| derived_poc_queue/triage_queue.jsonl | other/derived_poc_queue | 1046 | 127 | 28 | 891 | 12.1 | 0.0 | 1.7 | 14.8 | DEAD(891)/LOCAL(28) |
| derived_prove/candidate_ledger.jsonl | prove | 210 | 46 | 135 | 29 | 25.2 | 0.0 | 47.6 | 82.9 | GIT(164) |
| derived_rejections/rejection_corpus.jsonl | other/derived_rejections | 458 | 5 | 453 | 0 | 1.1 | 0.0 | 0.2 | 100.0 | GIT(453) |
| derived_siblings/candidates.jsonl | other/derived_siblings | 229 | 31 | 198 | 0 | 13.5 | 0.0 | 2.6 | 100.0 | LOCAL(198) |
| derived_siblings/hard_negatives.jsonl | other/derived_siblings | 8 | 1 | 7 | 0 | 12.5 | 0.0 | 12.5 | 100.0 | LOCAL(7) |
| derived_siblings/tasks.jsonl | other/derived_siblings | 221 | 30 | 191 | 0 | 13.6 | 0.0 | 2.3 | 100.0 | LOCAL(191) |
| derived_span_tasks/answer_key.jsonl | other/derived_span_tasks | 12504 | 0 | 0 | 12504 | 0.0 | 0.0 | 0.0 | 100.0 | LOCAL(12504) |
| derived_span_tasks/tasks.jsonl | other/derived_span_tasks | 12504 | 12504 | 0 | 0 | 100.0 | 0.0 | 0.0 | 100.0 | NONE |
| derived_v2_2/audit_ingestion_records.jsonl | other/derived_v2_2 | 16 | 0 | 0 | 16 | 0.0 | 0.0 | 0.0 | 0.0 | GIT(9)/DEAD(7) |
| derived_v2_2/audit_sources.jsonl | other/derived_v2_2 | 16 | 3 | 8 | 5 | 37.5 | 0.0 | 0.0 | 50.0 | GIT(10)/DEAD(3) |
| derived_v2_2/records.jsonl | other/derived_v2_2 | 137 | 43 | 94 | 0 | 31.4 | 0.0 | 1.5 | 100.0 | GIT(76)/DEAD(18) |
| derived_v3/candidate_ledger.jsonl | v3 | 7712 | 16 | 6340 | 1356 | 0.3 | 0.0 | 0.0 | 82.3 | LOCAL(7696) |
| derived_v3/corroborations.jsonl | v3 | 108 | 0 | 45 | 63 | 0.0 | 0.0 | 0.0 | 41.7 | DEAD(108) |
| derived_v3/corroborations_v31.jsonl | v3 | 0 | 0 | 0 | 0 | 0.0 | 0.0 | 0.0 | 0.0 | NONE |
| derived_v3/duplicates.jsonl | v3 | 108 | 0 | 45 | 63 | 0.0 | 0.0 | 0.0 | 41.7 | DEAD(108) |
| derived_v3/negatives.jsonl | v3 | 16 | 1 | 15 | 0 | 6.2 | 0.0 | 0.0 | 100.0 | LOCAL(15) |
| derived_v3/normalization_fragments.jsonl | v3 | 29176 | 25 | 6374 | 22777 | 0.1 | 0.0 | 0.0 | 20.0 | DEAD(22139)/LOCAL(7012) |
| derived_v3/normalization_overlay.jsonl | v3 | 9744 | 0 | 30 | 9714 | 0.0 | 0.0 | 0.3 | 0.0 | DEAD(8432)/GIT(1312) |
| derived_v3/normalized_records_preview.jsonl | v3 | 12504 | 538 | 11947 | 19 | 4.3 | 0.0 | 0.9 | 99.8 | LOCAL(11966) |
| derived_v3/patch_reviews.jsonl | v3 | 47 | 0 | 47 | 0 | 0.0 | 0.0 | 2.1 | 100.0 | GIT(47) |
| derived_v3/records.jsonl | v3 | 5467 | 509 | 4958 | 0 | 9.3 | 0.0 | 0.0 | 100.0 | LOCAL(4958) |
| derived_v4/admitted_ledger.jsonl | v4 | 5268 | 0 | 0 | 5268 | 29.6 | 0.0 | 1.4 | 74.4 | GIT(5268) |
| derived_v4/candidate_ledger.jsonl | v4 | 5270 | 0 | 0 | 5270 | 0.0 | 0.0 | 0.0 | 0.0 | DEAD(5270) |
| derived_v4/duplicate_ledger.jsonl | v4 | 2 | 0 | 0 | 2 | 100.0 | 0.0 | 0.0 | 100.0 | GIT(2) |
| derived_v4/quarantined_ledger.jsonl | v4 | 0 | 0 | 0 | 0 | 0.0 | 0.0 | 0.0 | 0.0 | NONE |
| distribution_v1/digests.jsonl | v4 | 6 | 1 | 5 | 0 | 16.7 | 0.0 | 0.0 | 100.0 | DEAD(5) |
| distribution_v1/records_v1.jsonl | v4 | 722 | 0 | 0 | 722 | 2.5 | 0.0 | 0.0 | 49.6 | DEAD(699)/GIT(23) |
| distribution_v1/records_v1_withheld_pointers.jsonl | v4 | 1794 | 0 | 1794 | 0 | 0.0 | 0.0 | 0.3 | 100.0 | GIT(1794) |
| distribution_v1/records_v4.jsonl | v4 | 5268 | 0 | 0 | 5268 | 1.0 | 0.0 | 0.0 | 29.7 | DEAD(5251)/GIT(17) |
| distribution_v1/records_v4_withheld_pointers.jsonl | v4 | 10070 | 0 | 10070 | 0 | 0.0 | 0.0 | 0.0 | 100.0 | GIT(10070) |
| distribution_v1/rights_ledger.jsonl | v4 | 12893 | 0 | 6 | 12887 | 0.0 | 0.0 | 0.0 | 100.0 | GIT(12786)/DEAD(107) |
| distribution_v1/withheld_harness.jsonl | v4 | 33 | 0 | 33 | 0 | 0.0 | 0.0 | 0.0 | 100.0 | GIT(33) |
| distribution_v1/withheld_pointers_other_layers.jsonl | v4 | 0 | 0 | 0 | 0 | 0.0 | 0.0 | 0.0 | 0.0 | NONE |
| experiments/reconstruction_log.jsonl | other/experiments | 155 | 0 | 0 | 155 | 0.0 | 0.0 | 0.0 | 0.0 | DEAD(155) |
| jsonl/errors.jsonl | v1 | 19 | 0 | 19 | 0 | 0.0 | 0.0 | 0.0 | 100.0 | DEAD(12)/GIT(7) |
| jsonl/exploits.jsonl | v1 | 155 | 77 | 0 | 78 | 99.4 | 1.3 | 23.9 | 100.0 | GIT(78) |
| jsonl/findings.jsonl | v1 | 264 | 135 | 21 | 108 | 87.9 | 8.0 | 22.0 | 100.0 | GIT(129) |
| jsonl/metadata.jsonl | v1 | 11 | 0 | 11 | 0 | 0.0 | 0.0 | 0.0 | 100.0 | GIT(11) |
| jsonl/negative_findings.jsonl | v1 | 458 | 272 | 6 | 180 | 83.8 | 0.2 | 10.3 | 100.0 | GIT(186) |
| jsonl/patches.jsonl | v1 | 38 | 10 | 0 | 28 | 100.0 | 0.0 | 0.0 | 100.0 | GIT(28) |
| jsonl/protocol.jsonl | v1 | 8 | 0 | 8 | 0 | 0.0 | 0.0 | 100.0 | 100.0 | GIT(8) |
| jsonl_ml/findings_cairo.jsonl | v2.2 | 8 | 7 | 1 | 0 | 87.5 | 0.0 | 12.5 | 100.0 | GIT(1) |
| jsonl_ml/findings_move.jsonl | v2.2 | 15 | 11 | 4 | 0 | 73.3 | 0.0 | 20.0 | 100.0 | GIT(3)/DEAD(1) |
| jsonl_ml/findings_reports.jsonl | v2.2 | 45 | 45 | 0 | 0 | 100.0 | 75.6 | 13.3 | 100.0 | NONE |
| jsonl_ml/findings_rust.jsonl | v2.2 | 18 | 10 | 8 | 0 | 55.6 | 0.0 | 0.0 | 100.0 | GIT(7)/DEAD(1) |
| jsonl_ml/findings_vyper.jsonl | v2.2 | 51 | 51 | 0 | 0 | 100.0 | 0.0 | 37.3 | 100.0 | NONE |
| jsonl_ml/sources_cairo.jsonl | v2.2 | 13 | 4 | 9 | 0 | 30.8 | 0.0 | 0.0 | 100.0 | GIT(8)/DEAD(1) |
| jsonl_ml/sources_move.jsonl | v2.2 | 18 | 7 | 11 | 0 | 38.9 | 0.0 | 11.1 | 100.0 | GIT(11) |
| jsonl_ml/sources_reports.jsonl | v2.2 | 5 | 0 | 5 | 0 | 0.0 | 0.0 | 0.0 | 100.0 | DEAD(5) |
| jsonl_ml/sources_rust.jsonl | v2.2 | 25 | 0 | 25 | 0 | 0.0 | 0.0 | 0.0 | 100.0 | GIT(23)/DEAD(2) |
| jsonl_ml/sources_vyper.jsonl | v2.2 | 51 | 0 | 51 | 0 | 0.0 | 0.0 | 0.0 | 100.0 | GIT(51) |
| jsonl_v3/findings.jsonl | v3 | 7712 | 16 | 6340 | 1356 | 0.3 | 0.0 | 0.0 | 82.3 | LOCAL(7696) |
| jsonl_v3/sources.jsonl | v3 | 18 | 0 | 0 | 18 | 0.0 | 0.0 | 0.0 | 5.6 | LOCAL(18) |
| jsonl_v4/findings.jsonl | v4 | 5268 | 0 | 0 | 5268 | 29.6 | 0.0 | 1.4 | 74.4 | GIT(5268) |
| jsonl_v4/sources.jsonl | v4 | 3 | 0 | 0 | 3 | 0.0 | 0.0 | 0.0 | 0.0 | GIT(3) |
| nextdata/_index_all_cleaned.jsonl | other/nextdata | 733 | 694 | 39 | 0 | 94.7 | 3.5 | 19.4 | 100.0 | DEAD(39) |
| nextdata/ml_dataset_part1.jsonl | other/nextdata | 232 | 218 | 14 | 0 | 94.0 | 6.5 | 21.1 | 100.0 | DEAD(14) |
| nextdata/ml_dataset_part2.jsonl | other/nextdata | 232 | 222 | 10 | 0 | 95.7 | 2.2 | 19.0 | 100.0 | DEAD(10) |
| nextdata/ml_dataset_part3.jsonl | other/nextdata | 230 | 216 | 14 | 0 | 93.9 | 2.2 | 20.0 | 100.0 | DEAD(14) |
| reports/poc_attempts.jsonl | other/reports | 56 | 7 | 39 | 10 | 12.5 | 0.0 | 62.5 | 42.9 | GIT(49) |
| splits_v2/quarantine.jsonl | other/splits_v2 | 2 | 2 | 0 | 0 | 100.0 | 0.0 | 0.0 | 100.0 | NONE |
| splits_v2/test.jsonl | other/splits_v2 | 253 | 82 | 29 | 142 | 80.2 | 1.2 | 16.6 | 100.0 | GIT(169)/DEAD(2) |
| splits_v2/train.jsonl | other/splits_v2 | 413 | 349 | 11 | 53 | 96.6 | 1.7 | 17.2 | 100.0 | GIT(62)/DEAD(2) |
| splits_v2/validation.jsonl | other/splits_v2 | 277 | 63 | 15 | 199 | 74.4 | 5.1 | 13.4 | 100.0 | GIT(212)/DEAD(2) |
| splits_v2_2/quarantine.jsonl | other/splits_v2_2 | 2 | 2 | 0 | 0 | 100.0 | 0.0 | 0.0 | 100.0 | NONE |
| splits_v2_2/test.jsonl | other/splits_v2_2 | 284 | 0 | 284 | 0 | 0.0 | 0.0 | 0.0 | 100.0 | DEAD(265)/GIT(19) |
| splits_v2_2/train.jsonl | other/splits_v2_2 | 489 | 0 | 489 | 0 | 0.0 | 0.0 | 0.0 | 100.0 | DEAD(457)/GIT(32) |
| splits_v2_2/validation.jsonl | other/splits_v2_2 | 307 | 0 | 307 | 0 | 0.0 | 0.0 | 0.0 | 100.0 | DEAD(287)/GIT(20) |
| splits_v3/quarantine.jsonl | other/splits_v3 | 0 | 0 | 0 | 0 | 0.0 | 0.0 | 0.0 | 0.0 | NONE |
| taxonomy/assignments_v1.jsonl | taxonomy | 418 | 18 | 244 | 156 | 4.3 | 0.0 | 0.0 | 62.7 | DEAD(400) |
| taxonomy/root_cause_v1.jsonl | taxonomy | 31 | 24 | 7 | 0 | 77.4 | 0.0 | 6.5 | 100.0 | DEAD(7) |
| tests/fixtures/broken/abbrev_commit_as_immutable/distribution_v1/records_v1_withheld_pointers.jsonl | other/tests | 1 | 0 | 0 | 1 | 0.0 | 0.0 | 0.0 | 0.0 | GIT(1) |
| tests/fixtures/broken/assignments_evidence_mismatch.jsonl | other/tests | 1 | 0 | 0 | 1 | 0.0 | 0.0 | 0.0 | 0.0 | DEAD(1) |
| tests/fixtures/broken/assignments_exclusive_pair.jsonl | other/tests | 1 | 0 | 0 | 1 | 0.0 | 0.0 | 0.0 | 0.0 | DEAD(1) |
| tests/fixtures/broken/assignments_ok.jsonl | other/tests | 3 | 0 | 0 | 3 | 0.0 | 0.0 | 0.0 | 0.0 | DEAD(3) |
| tests/fixtures/broken/assignments_unknown_category.jsonl | other/tests | 1 | 0 | 0 | 1 | 0.0 | 0.0 | 0.0 | 0.0 | DEAD(1) |
| tests/fixtures/broken/assignments_unknown_record.jsonl | other/tests | 1 | 0 | 0 | 1 | 0.0 | 0.0 | 0.0 | 0.0 | DEAD(1) |
| tests/fixtures/broken/assignments_unlabelled_no_reason.jsonl | other/tests | 1 | 0 | 0 | 1 | 0.0 | 0.0 | 0.0 | 0.0 | DEAD(1) |
| tests/fixtures/broken/attribution_free_digest/distribution_v1/digests.jsonl | other/tests | 1 | 0 | 1 | 0 | 0.0 | 0.0 | 0.0 | 100.0 | DEAD(1) |
| tests/fixtures/broken/bad_hash/distribution_v1/records_v4_withheld_pointers.jsonl | other/tests | 1 | 0 | 0 | 1 | 0.0 | 0.0 | 0.0 | 0.0 | GIT(1) |
| tests/fixtures/broken/contradictory_licence/jsonl_v4/findings.jsonl | other/tests | 2 | 0 | 0 | 2 | 0.0 | 0.0 | 0.0 | 0.0 | GIT(2) |
| tests/fixtures/broken/copied_unlicensed_source/distribution_v1/records_v1.jsonl | other/tests | 1 | 0 | 0 | 1 | 100.0 | 0.0 | 0.0 | 100.0 | GIT(1) |
| tests/fixtures/broken/poc_attempts/blocked_without_blocker_class.jsonl | other/tests | 2 | 0 | 0 | 2 | 0.0 | 0.0 | 0.0 | 0.0 | GIT(2) |
| tests/fixtures/broken/poc_attempts/claim_reproduced_without_assertion.jsonl | other/tests | 1 | 0 | 0 | 1 | 0.0 | 0.0 | 0.0 | 0.0 | GIT(1) |
| tests/fixtures/broken/poc_attempts/compile_failure_promoted_to_L4.jsonl | other/tests | 1 | 0 | 0 | 1 | 0.0 | 0.0 | 0.0 | 0.0 | GIT(1) |
| tests/fixtures/broken/poc_attempts/duplicate_attempt_id.jsonl | other/tests | 2 | 0 | 0 | 2 | 0.0 | 0.0 | 0.0 | 0.0 | GIT(2) |
| tests/fixtures/broken/poc_triage/eligible_with_blocker.jsonl | other/tests | 1 | 1 | 0 | 0 | 100.0 | 0.0 | 0.0 | 100.0 | NONE |
| tests/fixtures/broken/poc_triage/missing_pinned_revision.jsonl | other/tests | 1 | 0 | 1 | 0 | 0.0 | 0.0 | 100.0 | 100.0 | LOCAL(1) |
| tests/fixtures/broken/poc_triage/not_eligible_without_blocker.jsonl | other/tests | 1 | 1 | 0 | 0 | 100.0 | 0.0 | 100.0 | 100.0 | NONE |
| tests/fixtures/broken/poc_triage/poc_code_copied_not_pointed.jsonl | other/tests | 1 | 1 | 0 | 0 | 100.0 | 0.0 | 100.0 | 100.0 | NONE |
| tests/fixtures/broken/poc_triage/unknown_blocker_class.jsonl | other/tests | 1 | 1 | 0 | 0 | 100.0 | 0.0 | 0.0 | 100.0 | NONE |
| tests/fixtures/broken/taxonomy_facet_assignable.jsonl | other/tests | 31 | 24 | 7 | 0 | 77.4 | 0.0 | 6.5 | 100.0 | DEAD(7) |
| tests/fixtures/broken/taxonomy_impact_as_cause.jsonl | other/tests | 31 | 24 | 7 | 0 | 77.4 | 0.0 | 6.5 | 100.0 | DEAD(7) |
| tests/fixtures/broken/taxonomy_invented_swc.jsonl | other/tests | 31 | 24 | 7 | 0 | 77.4 | 0.0 | 6.5 | 100.0 | DEAD(7) |
| tests/fixtures/broken/taxonomy_no_exclusions.jsonl | other/tests | 31 | 24 | 7 | 0 | 77.4 | 0.0 | 6.5 | 100.0 | DEAD(7) |
| tests/fixtures/broken/taxonomy_no_map_no_reason.jsonl | other/tests | 31 | 24 | 7 | 0 | 77.4 | 0.0 | 6.5 | 100.0 | DEAD(7) |
| tests/fixtures/broken/taxonomy_primitive_as_cause.jsonl | other/tests | 31 | 24 | 7 | 0 | 77.4 | 0.0 | 6.5 | 100.0 | DEAD(7) |
| tests/fixtures/broken/taxonomy_unjustified_swc.jsonl | other/tests | 31 | 24 | 7 | 0 | 77.4 | 0.0 | 6.5 | 100.0 | DEAD(7) |
| tests/fixtures/broken/taxonomy_valid.jsonl | other/tests | 31 | 24 | 7 | 0 | 77.4 | 0.0 | 6.5 | 100.0 | DEAD(7) |
| tests/fixtures/good/jsonl_v4/findings.jsonl | other/tests | 2 | 0 | 0 | 2 | 0.0 | 0.0 | 0.0 | 0.0 | GIT(2) |
| training/attacker_reasoning.jsonl | other/training | 45 | 0 | 19 | 26 | 0.0 | 0.0 | 0.0 | 42.2 | DEAD(45) |
| training/canonical/detection.train.part-000.jsonl | other/training | 232 | 94 | 41 | 97 | 40.5 | 0.0 | 0.4 | 58.2 | DEAD(132)/GIT(6) |
| training/canonical/language.train.part-000.jsonl | other/training | 5000 | 1477 | 3486 | 37 | 29.5 | 0.0 | 1.1 | 99.3 | GIT(1977)/LOCAL(1526)/DEAD(20) |
| training/canonical/language.train.part-001.jsonl | other/training | 3050 | 245 | 2721 | 84 | 8.0 | 0.0 | 0.0 | 97.2 | LOCAL(2187)/DEAD(462)/GIT(156) |
| training/canonical/severity.train.part-000.jsonl | other/training | 5000 | 1565 | 3395 | 40 | 31.3 | 0.0 | 1.2 | 99.2 | GIT(1980)/LOCAL(1432)/DEAD(23) |
| training/canonical/severity.train.part-001.jsonl | other/training | 2661 | 232 | 2366 | 63 | 8.7 | 0.0 | 0.0 | 97.6 | LOCAL(2281)/GIT(109)/DEAD(39) |
| training/exploit_reasoning.jsonl | other/training | 0 | 0 | 0 | 0 | 0.0 | 0.0 | 0.0 | 0.0 | NONE |
| training/negative_reasoning.jsonl | other/training | 96 | 0 | 0 | 96 | 0.0 | 0.0 | 0.0 | 0.0 | DEAD(96) |
| training/patch_reasoning.jsonl | other/training | 0 | 0 | 0 | 0 | 0.0 | 0.0 | 0.0 | 0.0 | NONE |
| training/vulnerability_detection.jsonl | other/training | 45 | 37 | 4 | 4 | 82.2 | 0.0 | 4.4 | 91.1 | DEAD(5)/GIT(3) |
| wave1/00_governance/rights.jsonl | wave1 | 7 | 0 | 6 | 1 | 0.0 | 0.0 | 0.0 | 100.0 | DEAD(7) |
| wave1/00_governance/source_registry.jsonl | wave1 | 6 | 0 | 0 | 6 | 0.0 | 0.0 | 0.0 | 0.0 | DEAD(6) |
| wave1/01_dedup/overlap_manifest.jsonl | wave1 | 896 | 0 | 200 | 696 | 0.0 | 0.0 | 0.0 | 22.3 | DEAD(805)/GIT(91) |
| wave1/01_dedup/registry.jsonl | wave1 | 24074 | 0 | 794 | 23280 | 0.0 | 0.0 | 0.0 | 3.3 | DEAD(23227)/GIT(847) |
| wave1/03_candidates/c4_mitigation/issues.jsonl | wave1 | 812 | 0 | 31 | 781 | 0.0 | 0.0 | 0.0 | 3.8 | GIT(812) |
| wave1/03_candidates/formal_specs/rules.jsonl | wave1 | 7088 | 3807 | 2904 | 377 | 81.5 | 0.0 | 42.3 | 61.5 | GIT(3281) |
| wave1/03_candidates/ghsa_web3_netnew/candidates.jsonl | wave1 | 35 | 0 | 4 | 31 | 0.0 | 0.0 | 0.0 | 11.4 | GIT(35) |
| wave1/03_candidates/judge/issues.jsonl | wave1 | 1153 | 3 | 165 | 985 | 0.8 | 0.0 | 0.0 | 14.1 | GIT(1150) |
| wave1/03_candidates/markdown_two_revision/candidates.jsonl | wave1 | 786 | 10 | 662 | 114 | 4.2 | 0.0 | 0.0 | 82.4 | GIT(776) |
| wave1/03_candidates/reevmbench/harnesses.jsonl | wave1 | 67 | 0 | 0 | 67 | 0.0 | 0.0 | 0.0 | 0.0 | GIT(67) |
| wave1/04_admitted/c4_mitigation/findings.jsonl | wave1 | 531 | 0 | 15 | 516 | 0.0 | 0.0 | 0.0 | 2.8 | GIT(531) |
| wave1/04_admitted/formal_specs/findings.jsonl | wave1 | 895 | 362 | 469 | 64 | 71.3 | 0.0 | 2.8 | 50.5 | GIT(533) |
| wave1/04_admitted/ghsa_web3_netnew/findings.jsonl | wave1 | 31 | 0 | 2 | 29 | 0.0 | 0.0 | 0.0 | 6.5 | GIT(31) |
| wave1/04_admitted/judge/findings.jsonl | wave1 | 99 | 0 | 19 | 80 | 0.0 | 0.0 | 0.0 | 19.2 | GIT(99) |
| wave1/04_admitted/markdown_two_revision/findings.jsonl | wave1 | 575 | 10 | 500 | 65 | 5.6 | 0.0 | 0.0 | 84.7 | GIT(565) |
| wave1/04_admitted/reevmbench/findings.jsonl | wave1 | 55 | 0 | 0 | 55 | 0.0 | 0.0 | 0.0 | 0.0 | GIT(55) |
| wave1/benchmark_wave1/F_false_positive_rejection.jsonl | wave1 | 212 | 0 | 0 | 212 | 0.0 | 0.0 | 0.0 | 0.0 | GIT(212) |
| wave1/benchmark_wave1/Fa_rejection_evidence_axis_vector.jsonl | wave1 | 594 | 0 | 0 | 594 | 0.0 | 0.0 | 0.0 | 0.0 | GIT(594) |
| wave1/benchmark_wave1/Fb_duplicate_radar_pair.jsonl | wave1 | 527 | 0 | 0 | 527 | 0.0 | 0.0 | 0.0 | 0.0 | GIT(527) |
| wave1/benchmark_wave1/G_patch_verification.jsonl | wave1 | 531 | 0 | 0 | 531 | 0.0 | 0.0 | 0.0 | 0.0 | DEAD(531) |
| wave1/benchmark_wave1/J_verified_patch.jsonl | wave1 | 0 | 0 | 0 | 0 | 0.0 | 0.0 | 0.0 | 0.0 | NONE |
| wave1/benchmark_wave1/invariants.jsonl | wave1 | 297 | 183 | 114 | 0 | 61.6 | 0.0 | 4.0 | 100.0 | DEAD(114) |
| wave1/benchmark_wave1/prove_candidates.jsonl | wave1 | 18 | 0 | 0 | 18 | 0.0 | 0.0 | 0.0 | 0.0 | GIT(18) |
| wave1/benchmark_wave1/prove_incidents.jsonl | wave1 | 55 | 0 | 0 | 55 | 0.0 | 0.0 | 0.0 | 0.0 | GIT(55) |
| wave1/benchmark_wave1/severity_reconciliation.jsonl | wave1 | 606 | 0 | 0 | 606 | 0.0 | 0.0 | 0.0 | 0.0 | GIT(606) |
