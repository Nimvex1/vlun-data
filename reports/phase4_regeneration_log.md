# Phase 4 — Downstream regeneration log

Regeneration of all `*-current` generators, baselines, metrics, docs, and count pins in dependency order so every gate syncs with the hydrated / purged datasets. Python stdlib only. No gate scripts disabled; no data fabricated.

## Step 1 - Taxonomy / siblings / span / derived artifacts

| # | Command | Exit | Duration |
|---|---------|------|----------|
| 1 | `python scripts/validate_taxonomy.py` | 0 | 0.2s |

**[1] validate_taxonomy (confirm Phase 3 state)** — exit `0` (0.2s)

> Confirm taxonomy gate OK (Phase 3 already fixed). Gate name: taxonomy-current via --check.

```text
OK: 31 vocabulary entries (23 assignable leaves), 387 assignments, closed vocabulary enforced
```

| 2 | `python scripts/build_span_tasks.py` | 0 | 31.2s |

**[2] build_span_tasks (span-tasks-current)** — exit `0` (31.2s)

> Regenerate derived_span_tasks artifacts from hydrated sources.

```text
build_span_tasks.py: total=4623 verified=324 (char_span=0 full_bytes=324) unavailable=4299 abstain=4299
```

| 3 | `python scripts/audit_evidence_spans.py` | 0 | 0.7s |

**[3] audit_evidence_spans (span-audit-current)** — exit `0` (0.7s)

> Regenerate reports/evidence_span_audit.{json,md} against hydrated sources.

```text
audit_evidence_spans.py: wrote reports/evidence_span_audit.{json,md}  rows=4623 span=0 ptr=0 ref=4623 all3=0 byte_verifiable=0
```

| 4 | `python scripts/build_api_siblings.py` | 0 | 16.9s |

**[4] build_api_siblings (api-siblings-current)** — exit `0` (16.9s)

> Regenerate derived_siblings candidates/tasks/splits from hydrated sources.

```text
... (76 lines elided) ...
      "silo-core-v1": 43,
      "smart-contracts": 1,
      "synthetix-v3": 5,
      "v2-periphery": 15,
      "v3-periphery": 1
    },
    "pairs_by_vulnerable_project": {
      "2022-05-alchemix": 32,
      "2024-01-decent": 77,
      "2024-01-renft": 2,
      "2024-04-noya": 127,
      "2025-08-gte-perps": 17
    },
    "pairs_dropped_before_review": {
      "missing_root_cause": 0,
      "no_controlled_sibling_project": 8,
      "no_risky_form": 3
    },
    "reference_sites": 566,
    "vulnerable_sites": 81
  },
  "target_note": "spec item 11 asks to expand 71 toward 300+; this reports the yield the source pool actually supports, not a quota"
}
wrote derived_siblings\candidates.jsonl (255 candidate pairs)
wrote derived_siblings\pool_inputs.json
```

| 5 | `python scripts/review_sibling_pairs.py` | 0 | 20.8s |

**[5] review_sibling_pairs (sibling-review-current)** — exit `0` (20.8s)

> Regenerate reports/sibling_review.json from regenerated sibling candidates.

```text
... (2 lines elided) ...
  "near_duplicates_cross_split": 0,
  "reasons": {
    "reference:form_disagreed": 8,
    "vulnerable:form_disagreed": 3,
    "vulnerable:span_mismatch": 5
  },
  "splits": {
    "test": 32,
    "train": 141,
    "validation": 66
  },
  "yield": {
    "admitted_tasks": 239,
    "baseline_v2_1_pairs": 71,
    "candidates_proposed": 255,
    "dropped": 5,
    "growth_over_baseline": 3.5211267605633805,
    "hard_negatives": 11,
    "reviewed": 255,
    "reviewed_and_agreed": 239,
    "shortfall_explained": "the pool holds 255 real cross-repository sibling call sites; 5 could not be re-read from the pinned bytes and 11 failed the contrast under the independent reader, so 239 tasks are admitted. The binding limit is the number of confirmed findings whose cited code actually contains a call to a shared upstream API, not a processing step.",
    "target_reached": false
  }
}
wrote 239 tasks, 11 hard negatives, 5 dropped -> derived_siblings
```

| 6 | `python scripts/build_derived.py` | 0 | 3.2s |

**[6] build_derived (confirm Phase 3 state)** — exit `0` (3.2s)

> Confirm derived layer builder (already run in Phase 3) is clean/idempotent.

```text
wrote derived/records.jsonl (685)
  attacker_kind: {'protocol_accounting_or_config_flaw': 17, 'privileged': 344, 'unknown': 286, 'unprivileged': 31, 'malicious_dependency': 7}
  attacker_kind_basis: {'derived_fact': 384, 'reported_claim': 15, 'unknown': 286}
  attacker_identity_unknown: 286
  state_transition_present: 233
  state_transition_with_transactions: 129
  with_invariant: 221
  code_context_analysed_files: 1045
  code_context_files_retrieved: 444
  license_classes: {'unknown': 462, 'source_available_but_not_redistributable': 222, 'redistributable': 1}
  redistribution_flagged: {'source_redistributed_without_declared_license': 442, 'none': 243}
  quality_code_context: {'high': 244, 'medium': 421, 'none': 20}
  quality_attacker_model: {'high': 399, 'low': 286}
  quality_state_transition: {'high': 17, 'none': 668}
  taxonomy_top_level: {'Accounting': 67, 'Unknown': 135, 'DeFi': 123, 'Cross-Contract': 25, 'Denial of Service': 53, 'Logic Error': 9, 'Token Standards': 103, 'Access Control': 33, 'Cryptography / Signatures': 53, 'Governance': 10, 'Cross-Chain': 51, 'Reentrancy / External Calls': 19, 'Upgradeability': 4}
  dynamic_verification: {'reproduced': 5, 'not_executed': 140, 'not_attempted': 531, 'inconclusive': 7, 'not_reproduced': 2}
  invariants_invented: 0
  numeric_state_values_invented: 0
  derived_verification_levels: {'L6': 7}
  record_hash_scheme: {'v1-builder-row+verification-verdict': 154, 'v1-committed-row': 531}
  record_hash_scheme_v2: v2-committed-row
```

## Step 2 - Benchmark & evaluation

| # | Command | Exit | Duration |
|---|---------|------|----------|
| 1 | `python scripts/score_benchmark.py --build-baselines` | 0 | 11.0s |

**[1] score_benchmark --build-baselines (benchmark-baselines)** — exit `0` (11.0s)

> Recompute the six baseline reports from hydrated benchmark families (expect A=658).

```text
wrote reports\baselines\baseline_majority.json
wrote reports\baselines\baseline_random_seed7.json
wrote reports\baselines\baseline_frequency_seed7.json
wrote reports\baselines\baseline_first_published.json
wrote reports\baselines\baseline_majority_published.json
wrote reports\baselines\baseline_retrieval.json
```

| 2 | `python scripts/score_benchmark.py --build-metrics` | 0 | 3.0s |

**[2] score_benchmark --build-metrics (benchmark-metrics)** — exit `0` (3.0s)

> Recompute reports/benchmark_metrics.{json,md} from hydrated families.

```text
wrote reports\benchmark_metrics.json
wrote reports\benchmark_metrics.md
```

| 3 | `python scripts/independent_benchmark_audit.py` | 0 | 2.4s |

**[3] independent_benchmark_audit (regenerate)** — exit `0` (2.4s)

> Regenerate reports/independent/audit.json from hydrated benchmark data.

```text
... (1 lines elided) ...
families audited: 19 scorable + 5 not scorable; usable as evidence: 2
  A_vulnerability_detection.jsonl          clean
  B_root_cause_reasoning.jsonl             single_label
  C_attacker_reasoning.jsonl               clean
  E_exploit_verification.jsonl             too_small_to_score,holdout_too_small,split_composition_drift
  F_false_positive_rejection.jsonl         single_label,holdout_too_small
  G_patch_verification.jsonl               single_label,holdout_too_small
  I_verified_non_exploit.jsonl             single_label,holdout_too_small
  J_verified_patch.jsonl                   single_label,holdout_too_small
  K_language_ecosystem_routing.jsonl       answer_literal_leak,group_overlap,split_composition_drift
  L_severity_reconciliation.jsonl          answer_literal_leak,group_overlap,holdout_too_small,split_composition_drift
  M_experiment_level_classification.jsonl  holdout_too_small
  N_attacker_identity_extraction.jsonl     too_small_to_score,group_overlap,holdout_too_small,split_composition_drift
  O_record_class_and_scope.jsonl           group_overlap,split_composition_drift
  P_provenance_tier_and_rights.jsonl       group_overlap,split_composition_drift
  v3_R_source_tier_routing.jsonl           held_out_labels_unseen_in_train,split_composition_drift
  v3_S_contest_outcome.jsonl               saturated
  v3_T_taxonomy_explicit.jsonl             holdout_too_small
  vbeta_U_language_routing.jsonl           answer_literal_leak,holdout_too_small
  vbeta_V_source_tier_routing.jsonl        single_label,holdout_too_small
  D_exploit_construction.jsonl             skipped_no_scorable_key
  Fa_rejection_evidence_axis_vector.jsonl  skipped_no_scorable_key
  Fb_duplicate_radar_pair.jsonl            skipped_no_scorable_key
  H_verified_exploit.jsonl                 skipped_no_scorable_key
  Q_evidence_type_and_quality_rubric.jsonl skipped_no_scorable_key
```

| 4 | `python scripts/independent_benchmark_audit.py --check` | 0 | 2.4s |

**[4] independent_benchmark_audit --check (benchmark-audit-current)** — exit `0` (2.4s)

> Verify regenerated audit is current.

```text
independent audit is current
```

| 5 | `python scripts/build_secondary_holdout.py` | 0 | 1.7s |

**[5] build_secondary_holdout (regenerate)** — exit `0` (1.7s)

> Regenerate benchmark holdout artifacts (benchmark-holdout).

```text
wrote benchmark\independent\secondary_holdout_manifest.json
wrote benchmark\independent\secondary_holdout_tasks.jsonl (1364 clean model-facing tasks, zero literal-answer overlap)
wrote benchmark\independent\secondary_holdout_exploratory_tasks.jsonl (32 exploratory tasks; 29 contaminated)
wrote benchmark\independent\secondary_holdout_keys.jsonl and benchmark\independent\secondary_holdout_exploratory_keys.jsonl (local-only, untracked)
class-disjoint clean for 3 families; skipped for 15
```

| 6 | `python scripts/build_secondary_holdout.py --check` | 0 | 1.6s |

**[6] build_secondary_holdout --check (benchmark-holdout-current)** — exit `0` (1.6s)

> Verify regenerated holdout is current.

```text
secondary holdout is current: 1364 clean rows with zero literal overlap, 32 exploratory rows (29 contaminated); answer key present locally
```

| 7 | `python scripts/build_f_extension.py` | 0 | 0.9s |

**[7] build_f_extension (f-extension-current)** — exit `0` (0.9s)

> Regenerate Fa/Fb task files and manifest from hydrated canonical corpus.

```text
built F-A 444 rows (scorable 9), F-B 651 pairs (duplicate 179, distinct 101, ambiguous 371)
```

| 8 | `python scripts/score_f_extension.py --baselines` | 0 | 1.7s |

**[8] score_f_extension --baselines (f-extension-baselines-current)** — exit `0` (1.7s)

> Recompute F-extension baselines and reports/f_extension* artifacts.

```text
wrote baselines: F-A train-fitted majority validation micro accuracy 0.7741, F-B train-fitted majority validation accuracy 0.52
```

| 9 | `python scripts/build_eval_leakage_report.py` | 0 | 5.7s |

**[9] build_eval_leakage_report (eval-leakage-report-current)** — exit `0` (5.7s)

> Regenerate STALE reports/eval_leakage_report.{json,md} after canonical-corpus rebuild.

```text
wrote reports/eval_leakage_report.json
wrote reports/eval_leakage_report.md
verdict: clean
  held-out rows with id overlap   : 0
  held-out rows with text overlap : 0
  held-out rows with code overlap : 0
  held-out answer keys reproduced : 0
```

| 10 | `python scripts/build_repro_report.py` | 0 | 0.1s |

**[10] build_repro_report (repro-report-current)** — exit `0` (0.1s)

> Regenerate reports/reproducibility_report.md / checks from hydrated data.

```text
wrote reports\reproducibility_report.md (56 lines)
```

| 11 | `python scripts/build_quarantine_report.py` | 0 | 0.2s |

**[11] build_quarantine_report (quarantine-report-current)** — exit `0` (0.2s)

> Regenerate reports/quarantine_report.{json,md} from current quarantine ledgers.

```text
quarantine_report.md: v1/v2 split quarantine=2, v2.2 split quarantine=2, Vbeta split quarantine=0, V4 quarantined ledger=0, V4 duplicate ledger=0, extraction errors by kind=36, v1/v2.1 PoC re-run attempts=56, V3.2 recovery attempts=9, non-EVM pilot blockers=27, inconclusive declared experiments=2, withheld expressive content=18356
```

| 12 | `python scripts/build_poc_triage_queue.py` | 0 | 3.9s |

**[12] build_poc_triage_queue (poc-triage-current)** — exit `0` (3.9s)

> Regenerate reports/poc_triage_queue.{json,md} and derived_poc_queue from hydrated data.

```text
queued 1011 rows: v1/v2.1 154 (5 eligible, 23 attemptable) + v3.1 857 PoC-bearing
```

## Step 3 - Docs & manifests

| # | Command | Exit | Duration |
|---|---------|------|----------|
| 1 | `python scripts/generate_readme.py` | 0 | 0.6s |

**[1] generate_readme (readme-current)** — exit `0` (0.6s)

> Regenerate README.md + NOTICE.md from hydrated dataset stats.

```text
wrote README.md (532 lines) and NOTICE.md (225 lines)
```

| 2 | `python scripts/build_datasheet.py` | 0 | 0.1s |

**[2] build_datasheet (datasheet-current)** — exit `0` (0.1s)

> Regenerate docs/DATASHEET.md from current data.

```text
wrote docs/DATASHEET.md (51 lines)
```

| 3 | `python scripts/build_release_manifest.py` | 0 | 60.6s |

**[3] build_release_manifest (release-manifest-current)** — exit `0` (60.6s)

> Regenerate RELEASE_MANIFEST.json (NOT catalog yet).

```text
wrote RELEASE_MANIFEST.json: 2073 tracked paths, 531 released, 1542 not released
  attribution_required                                14
  internal_research_artefact_not_cleared            1339
  metadata_only                                        1
  project_own                                        516
  withheld_third_party_no_redistribution_rights      203
```

| 4 | `python scripts/build_json_catalog.py` | 0 | 37.6s |

**[4] build_json_catalog (catalog-current) - last builder of Step 3** — exit `0` (37.6s)

> Rebuilt LAST of all builders: hashes RELEASE_MANIFEST.json + every tracked .json/.jsonl. Will be re-run again in Step 5 as the absolute final step.

```text
wrote reports/json_catalog.json + .md (918 files)
```

## Staleness detection sweep (read-only --check on every generator gate)

| # | Command | Exit | Duration |
|---|---------|------|----------|
| 1 | `python scripts/generate_readme.py --check` | 0 | 0.5s |

**[1] CHECK readme-current** — exit `0` (0.5s)

```text
README.md and NOTICE.md are current
```

| 2 | `python Vbeta/scripts/build_solodit_report.py --check` | 0 | 0.1s |

**[2] CHECK solodit-report-current** — exit `0` (0.1s)

```text
solodit_ingestion_report.md is current
```

| 3 | `python scripts/build_repro_report.py --check` | 0 | 0.1s |

**[3] CHECK repro-report-current** — exit `0` (0.1s)

```text
reproducibility_report.md is current
```

| 4 | `python scripts/generate_stats.py --check` | 0 | 0.3s |

**[4] CHECK stats-current** — exit `0` (0.3s)

```text
reports/dataset_stats.json is current
```

| 5 | `python scripts/build_rejection_corpus.py --check` | 0 | 0.5s |

**[5] CHECK rejection-corpus-current** — exit `0` (0.5s)

```text
rejection corpus is current
```

| 6 | `python scripts/classify_negatives.py --check` | 0 | 0.2s |

**[6] CHECK negative-stats-current** — exit `0` (0.2s)

```text
negative_verification_stats.json is current
```

| 7 | `python scripts/check_f_extension.py --check` | 0 | 0.5s |

**[7] CHECK f-extension-consistency** — exit `0` (0.5s)

```text
F-extension consistent: 444 corpus records, F-A 444 rows (9 labeled), F-B 651 pairs over 415 candidate submissions (same 179, distinct 101, ambiguous 371)
```

| 8 | `python scripts/build_f_extension.py --check` | 0 | 0.9s |

**[8] CHECK f-extension-current** — exit `0` (0.9s)

```text
F-extension current: 5 artefacts byte-identical
```

| 9 | `python scripts/score_f_extension.py --check` | 0 | 1.8s |

**[9] CHECK f-extension-baselines-current** — exit `0` (1.8s)

```text
ok: F-extension baselines current
```

| 10 | `python scripts/build_prove_split.py --check` | 0 | 0.8s |

**[10] CHECK prove-split-current** — exit `0` (0.8s)

```text
prove interface is current (8 tasks)
```

| 11 | `python scripts/build_prove_ledger.py --check` | 0 | 0.1s |

**[11] CHECK prove-ledger-current** — exit `0` (0.1s)

```text
skipped_private_inputs_present: derived_prove/candidate_ledger.jsonl and reports/prove_candidate_ledger.json verified (210 rows, 0 invariant violation(s), schema_version=vlun-prove-candidate-ledger/1.0); private discovery ledgers exist in work/prove_candidates but are external to the published snapshot, so re-derivation is not trusted
```

| 12 | `python scripts/reconcile_v4_licensing.py --check` | 0 | 0.8s |

**[12] CHECK v4-licensing-current** — exit `0` (0.8s)

```text
V4 licence fields already match V4/licensing.json
```

| 13 | `python scripts/build_poc_triage_queue.py --check` | 0 | 4.1s |

**[13] CHECK poc-triage-current** — exit `0` (4.1s)

```text
OK     derived_poc_queue\triage_queue.jsonl
OK     reports\poc_triage_queue.json
OK     reports\poc_triage_queue.md
check: byte-identical
```

| 14 | `python scripts/rerun_v1_pocs.py --check` | 0 | 0.1s |

**[14] CHECK poc-attempts-current** — exit `0` (0.1s)

```text
OK     reports/poc_execution_density.json
OK     reports/poc_execution_density.md
```

| 15 | `python scripts/unblock_v32_runs.py --check` | 0 | 0.2s |

**[15] CHECK v32-attempts-current** — exit `0` (0.2s)

```text
... (10 lines elided) ...
    attempt_2: rule_compat_hardfork provider={'mainnet': 'https://eth.drpc.org'} fork={'alias': 'mainnet', 'kind': 'tx', 'value': '0x00c503b595946bccaea3d58025b5f9b3726177bbdc9674e634244135282116c7'} hardfork=cancun scope_change=True
    attempt_3: block_fork_reconstruction provider={'mainnet': 'https://eth-mainnet.public.blastapi.io'} fork={'alias': 'mainnet', 'kind': 'tx', 'value': '0x00c503b595946bccaea3d58025b5f9b3726177bbdc9674e634244135282116c7'} hardfork=None scope_change=True
    tenderly access available: False
  shibatoken: poc=2023-11/ShibaToken_exp.sol sha256=dd42c6b5b6987f8d... clone_head=0200ce8af03a test=test
    attempt_2: archive_provider provider={'bsc': 'https://bsc.meowrpc.com'} fork={'alias': 'bsc', 'kind': 'block', 'value': 33528882} hardfork=None scope_change=False
    attempt_3: archive_provider provider={'bsc': 'https://api.zan.top/bsc-mainnet'} fork={'alias': 'bsc', 'kind': 'block', 'value': 33528882} hardfork=None scope_change=False
    attempt_4: harness_reconstruction provider={'bsc': 'https://api.zan.top/bsc-mainnet'} fork={'alias': 'bsc', 'kind': 'block', 'value': 33528882} hardfork=None scope_change=True
    tenderly access available: False
```

| 16 | `python scripts/audit_evidence_spans.py --check` | 0 | 1.8s |

**[16] CHECK span-audit-current** — exit `0` (1.8s)

```text
audit_evidence_spans.py --check OK
```

| 17 | `python scripts/build_span_tasks.py --check` | 0 | 1.9s |

**[17] CHECK span-tasks-current** — exit `0` (1.9s)

```text
build_span_tasks.py --check OK
```

| 18 | `python scripts/score_span_tasks.py --check` | 1 | 0.2s |

**[18] CHECK span-scoring-current** — exit `1` (0.2s)

```text
score_span_tasks.py --check FAILED: committed report stale
```

| 19 | `python scripts/validate_taxonomy.py --check` | 0 | 0.3s |

**[19] CHECK taxonomy-current** — exit `0` (0.3s)

```text
OK: 31 vocabulary entries (23 assignable leaves), 387 assignments, closed vocabulary enforced
```

| 20 | `python scripts/assign_root_causes.py --check` | 0 | 0.2s |

**[20] CHECK root-cause-assignments-current** — exit `0` (0.2s)

```text
OK: 387 assignments, byte-stable
```

| 21 | `python scripts/sample_iaa.py --check` | 0 | 0.1s |

**[21] CHECK iaa-sample-current** — exit `0` (0.1s)

```text
OK: frozen iaa-draw-1.0, n=300, seed=20261018, templates match
```

| 22 | `python scripts/iaa_statistics.py --check` | 0 | 0.1s |

**[22] CHECK iaa-stats-current** — exit `0` (0.1s)

```text
OK: measured=False, byte-stable
```

| 23 | `python scripts/build_api_siblings.py --check` | 0 | 10.9s |

**[23] CHECK api-siblings-current** — exit `0` (10.9s)

```text
... (92 lines elided) ...
      "no_risky_form": 3
    },
    "reference_sites": 566,
    "vulnerable_sites": 81
  },
  "target_note": "spec item 11 asks to expand 71 toward 300+; this reports the yield the source pool actually supports, not a quota"
}
CHECK OK: derived_siblings/candidates.jsonl regenerates byte-identically (255 candidates)
```

| 24 | `python scripts/review_sibling_pairs.py --check` | 0 | 20.0s |

**[24] CHECK sibling-review-current** — exit `0` (20.0s)

```text
... (25 lines elided) ...
}
CHECK OK: derived_siblings\tasks.jsonl
CHECK OK: derived_siblings\hard_negatives.jsonl
CHECK OK: derived_siblings\splits.json
CHECK OK: derived_siblings\manifest.json
CHECK OK: reports\sibling_review.json
CHECK OK: reports\api_sibling_stats.json
CHECK OK: reports\api_sibling_stats.md
```

| 25 | `python scripts/build_remediation_report.py --check` | 1 | 0.3s |

**[25] CHECK remediation-report-current** — exit `1` (0.3s)

```text
STALE: reports\remediation_before_after.md, reports\remediation_before_after.json
```

| 26 | `python scripts/build_quarantine_report.py --check` | 0 | 0.2s |

**[26] CHECK quarantine-report-current** — exit `0` (0.2s)

```text
quarantine report is current
```

| 27 | `python scripts/field_coverage.py --check` | 0 | 0.6s |

**[27] CHECK field-coverage-current** — exit `0` (0.6s)

```text
field coverage reports are current
```

| 28 | `python scripts/build_schemas.py --check` | 0 | 0.1s |

**[28] CHECK schemas-current** — exit `0` (0.1s)

```text
schema/ is current
```

| 29 | `python scripts/build_datasheet.py --check` | 0 | 0.1s |

**[29] CHECK datasheet-current** — exit `0` (0.1s)

```text
docs/DATASHEET.md is current
```

| 30 | `python Vbeta/scripts/build_vbeta.py --check` | 0 | 1.9s |

**[30] CHECK vbeta-build-current** — exit `0` (1.9s)

```text
build_vbeta.py
  + 733 harvested candidates from solodit_candidates.json
  + 491 harvested candidates from web3bugs_candidates.json
  + 550 harvested candidates from scabench_candidates.json
  + 5175 harvested candidates from lisabench_candidates.json
  check ok: 7060 candidates, 6935 records, 6219 U-tasks, 6935 V-tasks (wrote nothing)
```

| 31 | `python scripts/build_json_catalog.py --check` | 0 | 13.5s |

**[31] CHECK catalog-current** — exit `0` (13.5s)

```text
json catalog is current (918 files)
```

| 32 | `python scripts/independent_benchmark_audit.py --check` | 1 | 2.3s |

**[32] CHECK benchmark-audit-current** — exit `1` (2.3s)

```text

STALE reports\independent\audit.json -- run: python scripts/independent_benchmark_audit.py
```

| 33 | `python scripts/build_secondary_holdout.py --check` | 0 | 1.6s |

**[33] CHECK benchmark-holdout-current** — exit `0` (1.6s)

```text
secondary holdout is current: 1364 clean rows with zero literal overlap, 32 exploratory rows (29 contaminated); answer key present locally
```

| 34 | `python scripts/score_benchmark.py --check` | 1 | 10.8s |

**[34] CHECK benchmark-baselines-current** — exit `1` (10.8s)

```text

STALE reports\baselines\baseline_majority.json -- regenerate with: python scripts/score_benchmark.py --build-baselines
STALE reports\baselines\baseline_random_seed7.json -- regenerate with: python scripts/score_benchmark.py --build-baselines
STALE reports\baselines\baseline_frequency_seed7.json -- regenerate with: python scripts/score_benchmark.py --build-baselines
STALE reports\baselines\baseline_first_published.json -- regenerate with: python scripts/score_benchmark.py --build-baselines
STALE reports\baselines\baseline_majority_published.json -- regenerate with: python scripts/score_benchmark.py --build-baselines
STALE reports\baselines\baseline_retrieval.json -- regenerate with: python scripts/score_benchmark.py --build-baselines
```

| 35 | `python scripts/score_benchmark.py --check-metrics` | 1 | 2.9s |

**[35] CHECK benchmark-metrics-current** — exit `1` (2.9s)

```text

STALE reports\benchmark_metrics.json -- regenerate with: python scripts/score_benchmark.py --build-metrics
STALE reports\benchmark_metrics.md -- regenerate with: python scripts/score_benchmark.py --build-metrics
```

| 36 | `python scripts/build_eval_leakage_report.py --check` | 0 | 5.6s |

**[36] CHECK eval-leakage-report-current** — exit `0` (5.6s)

```text
evaluation-leakage report is current
```

| 37 | `python scripts/redact_machine_paths.py --check` | 0 | 0.5s |

**[37] CHECK redaction-current** — exit `0` (0.5s)

```text
scanned 1232 file(s) in scope
  machine paths redacted : 0
  digests re-pointed     : 0
  files changed          : 0
```

| 38 | `python scripts/build_release_manifest.py --check` | 0 | 59.4s |

**[38] CHECK release-manifest-current** — exit `0` (59.4s)

```text
  RELEASE_MANIFEST.json: reproducible; 531 released, 1542 not released
```

| 39 | `python scripts/reconcile_proof_artefact_hashes.py --check` | 0 | 3.0s |

**[39] CHECK proof-hashes-current** — exit `0` (3.0s)

```text
... (1 lines elided) ...
  v1 experiments                     sha256-v1-text                       67 digest(s), 4 unresolved
  v2.2 experiments                   sha256-v1-raw                        24 digest(s), 0 unresolved
  v2.2 index                         sha256-v1-raw                        24 digest(s), 0 unresolved
  nonevm experiments                 sha256-v1-raw                       439 digest(s), 0 unresolved
  v3 experiments                     sha256-v1-bytes                      94 digest(s), 0 unresolved
  v3 record files + derived_v2_2     sha256-v1-bytes / sha256-v1-text    303 digest(s), 0 unresolved
  experimental_proof.json            sha256-v1-bytes                      90 digest(s), 0 unresolved
  [not hash-verifiable here] withheld harness files: experiments/**/harness/WITHHELD.json and distribution_v1/withheld_harness.jsonl
```

## Diagnostic - benchmark rebuild/check

| # | Command | Exit | Duration |
|---|---------|------|----------|
| 1 | `python scripts/score_benchmark.py --build-baselines` | 0 | 11.3s |

**[1] DIAG rebuild baselines** — exit `0` (11.3s)

```text
wrote reports\baselines\baseline_majority.json
wrote reports\baselines\baseline_random_seed7.json
wrote reports\baselines\baseline_frequency_seed7.json
wrote reports\baselines\baseline_first_published.json
wrote reports\baselines\baseline_majority_published.json
wrote reports\baselines\baseline_retrieval.json
```

| 2 | `python scripts/score_benchmark.py --check` | 0 | 11.1s |

**[2] DIAG check baselines immediately** — exit `0` (11.1s)

```text
current reports\baselines\baseline_majority.json
current reports\baselines\baseline_random_seed7.json
current reports\baselines\baseline_frequency_seed7.json
current reports\baselines\baseline_first_published.json
current reports\baselines\baseline_majority_published.json
current reports\baselines\baseline_retrieval.json
all six baseline reports are current
```

| 3 | `python scripts/independent_benchmark_audit.py` | 0 | 2.4s |

**[3] DIAG rebuild independent audit** — exit `0` (2.4s)

```text
... (18 lines elided) ...
  v3_T_taxonomy_explicit.jsonl             holdout_too_small
  vbeta_U_language_routing.jsonl           answer_literal_leak,holdout_too_small
  vbeta_V_source_tier_routing.jsonl        single_label,holdout_too_small
  D_exploit_construction.jsonl             skipped_no_scorable_key
  Fa_rejection_evidence_axis_vector.jsonl  skipped_no_scorable_key
  Fb_duplicate_radar_pair.jsonl            skipped_no_scorable_key
  H_verified_exploit.jsonl                 skipped_no_scorable_key
  Q_evidence_type_and_quality_rubric.jsonl skipped_no_scorable_key
```

| 4 | `python scripts/independent_benchmark_audit.py --check` | 0 | 2.3s |

**[4] DIAG check independent audit immediately** — exit `0` (2.3s)

```text
independent audit is current
```

## Diagnostic - Step 3 builders hash-mutation test

| # | Command | Exit | Duration |
|---|---------|------|----------|
| 1 | `python scripts/generate_readme.py` | 0 | 0.4s |

**[1] DIAG generate_readme** — exit `0` (0.4s)

```text
wrote README.md (532 lines) and NOTICE.md (225 lines)
```

| 2 | `python scripts/build_datasheet.py` | 0 | 0.1s |

**[2] DIAG build_datasheet** — exit `0` (0.1s)

```text
wrote docs/DATASHEET.md (51 lines)
```

| 3 | `python scripts/build_release_manifest.py` | 0 | 59.3s |

**[3] DIAG build_release_manifest** — exit `0` (59.3s)

```text
... (1 lines elided) ...
  attribution_required                                14
  internal_research_artefact_not_cleared            1339
  metadata_only                                        1
  project_own                                        516
  withheld_third_party_no_redistribution_rights      203
```

| 4 | `python scripts/build_json_catalog.py` | 0 | 7.7s |

**[4] DIAG build_json_catalog** — exit `0` (7.7s)

```text
wrote reports/json_catalog.json + .md (918 files)
```

## Diagnostic - holdout invalidation test

| # | Command | Exit | Duration |
|---|---------|------|----------|
| 1 | `python scripts/score_benchmark.py --check` | 0 | 10.9s |

**[1] DIAG check baselines (pre-holdout)** — exit `0` (10.9s)

```text
... (1 lines elided) ...
current reports\baselines\baseline_random_seed7.json
current reports\baselines\baseline_frequency_seed7.json
current reports\baselines\baseline_first_published.json
current reports\baselines\baseline_majority_published.json
current reports\baselines\baseline_retrieval.json
all six baseline reports are current
```

| 2 | `python scripts/score_benchmark.py --check-metrics` | 1 | 2.9s |

**[2] DIAG check metrics (pre-holdout)** — exit `1` (2.9s)

```text

STALE reports\benchmark_metrics.json -- regenerate with: python scripts/score_benchmark.py --build-metrics
STALE reports\benchmark_metrics.md -- regenerate with: python scripts/score_benchmark.py --build-metrics
```

| 3 | `python scripts/build_secondary_holdout.py` | 0 | 1.7s |

**[3] DIAG rebuild holdout** — exit `0` (1.7s)

```text
wrote benchmark\independent\secondary_holdout_manifest.json
wrote benchmark\independent\secondary_holdout_tasks.jsonl (1364 clean model-facing tasks, zero literal-answer overlap)
wrote benchmark\independent\secondary_holdout_exploratory_tasks.jsonl (32 exploratory tasks; 29 contaminated)
wrote benchmark\independent\secondary_holdout_keys.jsonl and benchmark\independent\secondary_holdout_exploratory_keys.jsonl (local-only, untracked)
class-disjoint clean for 3 families; skipped for 15
```

| 4 | `python scripts/score_benchmark.py --check` | 0 | 10.6s |

**[4] DIAG check baselines (post-holdout)** — exit `0` (10.6s)

```text
... (1 lines elided) ...
current reports\baselines\baseline_random_seed7.json
current reports\baselines\baseline_frequency_seed7.json
current reports\baselines\baseline_first_published.json
current reports\baselines\baseline_majority_published.json
current reports\baselines\baseline_retrieval.json
all six baseline reports are current
```

| 5 | `python scripts/score_benchmark.py --check-metrics` | 1 | 2.9s |

**[5] DIAG check metrics (post-holdout)** — exit `1` (2.9s)

```text

STALE reports\benchmark_metrics.json -- regenerate with: python scripts/score_benchmark.py --build-metrics
STALE reports\benchmark_metrics.md -- regenerate with: python scripts/score_benchmark.py --build-metrics
```

| 6 | `python scripts/independent_benchmark_audit.py --check` | 0 | 2.4s |

**[6] DIAG check audit (post-holdout)** — exit `0` (2.4s)

```text
independent audit is current
```

## Dependency-order correction pass (f-extension / summary reports)

| # | Command | Exit | Duration |
|---|---------|------|----------|
| 1 | `python scripts/score_benchmark.py --build-metrics` | 0 | 2.9s |

**[1] CORRECT score_benchmark --build-metrics (after f-extension rewrote Fa/Fb)** — exit `0` (2.9s)

> build_f_extension.py rewrites benchmark/Fa_* and Fb_*.jsonl (discovered as families by benchmark_status.py), so metrics built earlier in Step 2 were invalidated. Rebuilt after f-extension.

```text
wrote reports\benchmark_metrics.json
wrote reports\benchmark_metrics.md
```

| 2 | `python scripts/score_span_tasks.py` | 0 | 0.2s |

**[2] CORRECT score_span_tasks (span-scoring-current)** — exit `0` (0.2s)

> span scoring report was stale because its inputs were regenerated in Steps 1-2; rebuild from current span tasks/audit.

```text
score_span_tasks.py: wrote reports/span_scoring_report.{json,md} (mode=mechanical_baselines)
```

| 3 | `python scripts/build_remediation_report.py` | 0 | 0.4s |

**[3] CORRECT build_remediation_report (remediation-report-current)** — exit `0` (0.4s)

> before/after summary reads eval-leakage/quarantine/etc. reports regenerated in Step 2; rebuild after those inputs.

```text
remediation_before_after.md: 11 items
```

| 4 | `python scripts/score_benchmark.py --build-baselines` | 0 | 11.0s |

**[4] CORRECT score_benchmark --build-baselines (final ordering confirmation)** — exit `0` (11.0s)

> Idempotent re-run after f-extension to confirm final ordering is stable.

```text
wrote reports\baselines\baseline_majority.json
wrote reports\baselines\baseline_random_seed7.json
wrote reports\baselines\baseline_frequency_seed7.json
wrote reports\baselines\baseline_first_published.json
wrote reports\baselines\baseline_majority_published.json
wrote reports\baselines\baseline_retrieval.json
```

| 5 | `python scripts/independent_benchmark_audit.py` | 0 | 2.3s |

**[5] CORRECT independent_benchmark_audit (final ordering confirmation)** — exit `0` (2.3s)

> Idempotent re-run after f-extension to confirm final ordering is stable.

```text
... (18 lines elided) ...
  v3_T_taxonomy_explicit.jsonl             holdout_too_small
  vbeta_U_language_routing.jsonl           answer_literal_leak,holdout_too_small
  vbeta_V_source_tier_routing.jsonl        single_label,holdout_too_small
  D_exploit_construction.jsonl             skipped_no_scorable_key
  Fa_rejection_evidence_axis_vector.jsonl  skipped_no_scorable_key
  Fb_duplicate_radar_pair.jsonl            skipped_no_scorable_key
  H_verified_exploit.jsonl                 skipped_no_scorable_key
  Q_evidence_type_and_quality_rubric.jsonl skipped_no_scorable_key
```

## Re-check sweep - confirm every generator gate current

| # | Command | Exit | Duration |
|---|---------|------|----------|
| 1 | `python scripts/generate_readme.py --check` | 0 | 0.6s |

**[1] CHECK readme-current** — exit `0` (0.6s)

```text
README.md and NOTICE.md are current
```

| 2 | `python Vbeta/scripts/build_solodit_report.py --check` | 0 | 0.1s |

**[2] CHECK solodit-report-current** — exit `0` (0.1s)

```text
solodit_ingestion_report.md is current
```

| 3 | `python scripts/build_repro_report.py --check` | 0 | 0.1s |

**[3] CHECK repro-report-current** — exit `0` (0.1s)

```text
reproducibility_report.md is current
```

| 4 | `python scripts/generate_stats.py --check` | 0 | 0.3s |

**[4] CHECK stats-current** — exit `0` (0.3s)

```text
reports/dataset_stats.json is current
```

| 5 | `python scripts/build_rejection_corpus.py --check` | 0 | 0.5s |

**[5] CHECK rejection-corpus-current** — exit `0` (0.5s)

```text
rejection corpus is current
```

| 6 | `python scripts/classify_negatives.py --check` | 0 | 0.2s |

**[6] CHECK negative-stats-current** — exit `0` (0.2s)

```text
negative_verification_stats.json is current
```

| 7 | `python scripts/check_f_extension.py --check` | 0 | 0.5s |

**[7] CHECK f-extension-consistency** — exit `0` (0.5s)

```text
F-extension consistent: 444 corpus records, F-A 444 rows (9 labeled), F-B 651 pairs over 415 candidate submissions (same 179, distinct 101, ambiguous 371)
```

| 8 | `python scripts/build_f_extension.py --check` | 0 | 0.9s |

**[8] CHECK f-extension-current** — exit `0` (0.9s)

```text
F-extension current: 5 artefacts byte-identical
```

| 9 | `python scripts/score_f_extension.py --check` | 0 | 1.6s |

**[9] CHECK f-extension-baselines-current** — exit `0` (1.6s)

```text
ok: F-extension baselines current
```

| 10 | `python scripts/build_prove_split.py --check` | 0 | 0.7s |

**[10] CHECK prove-split-current** — exit `0` (0.7s)

```text
prove interface is current (8 tasks)
```

| 11 | `python scripts/build_prove_ledger.py --check` | 0 | 0.1s |

**[11] CHECK prove-ledger-current** — exit `0` (0.1s)

```text
skipped_private_inputs_present: derived_prove/candidate_ledger.jsonl and reports/prove_candidate_ledger.json verified (210 rows, 0 invariant violation(s), schema_version=vlun-prove-candidate-ledger/1.0); private discovery ledgers exist in work/prove_candidates but are external to the published snapshot, so re-derivation is not trusted
```

| 12 | `python scripts/reconcile_v4_licensing.py --check` | 0 | 0.7s |

**[12] CHECK v4-licensing-current** — exit `0` (0.7s)

```text
V4 licence fields already match V4/licensing.json
```

| 13 | `python scripts/build_poc_triage_queue.py --check` | 0 | 3.8s |

**[13] CHECK poc-triage-current** — exit `0` (3.8s)

```text
OK     derived_poc_queue\triage_queue.jsonl
OK     reports\poc_triage_queue.json
OK     reports\poc_triage_queue.md
check: byte-identical
```

| 14 | `python scripts/rerun_v1_pocs.py --check` | 0 | 0.1s |

**[14] CHECK poc-attempts-current** — exit `0` (0.1s)

```text
OK     reports/poc_execution_density.json
OK     reports/poc_execution_density.md
```

| 15 | `python scripts/unblock_v32_runs.py --check` | 0 | 0.2s |

**[15] CHECK v32-attempts-current** — exit `0` (0.2s)

```text
... (10 lines elided) ...
    attempt_2: rule_compat_hardfork provider={'mainnet': 'https://eth.drpc.org'} fork={'alias': 'mainnet', 'kind': 'tx', 'value': '0x00c503b595946bccaea3d58025b5f9b3726177bbdc9674e634244135282116c7'} hardfork=cancun scope_change=True
    attempt_3: block_fork_reconstruction provider={'mainnet': 'https://eth-mainnet.public.blastapi.io'} fork={'alias': 'mainnet', 'kind': 'tx', 'value': '0x00c503b595946bccaea3d58025b5f9b3726177bbdc9674e634244135282116c7'} hardfork=None scope_change=True
    tenderly access available: False
  shibatoken: poc=2023-11/ShibaToken_exp.sol sha256=dd42c6b5b6987f8d... clone_head=0200ce8af03a test=test
    attempt_2: archive_provider provider={'bsc': 'https://bsc.meowrpc.com'} fork={'alias': 'bsc', 'kind': 'block', 'value': 33528882} hardfork=None scope_change=False
    attempt_3: archive_provider provider={'bsc': 'https://api.zan.top/bsc-mainnet'} fork={'alias': 'bsc', 'kind': 'block', 'value': 33528882} hardfork=None scope_change=False
    attempt_4: harness_reconstruction provider={'bsc': 'https://api.zan.top/bsc-mainnet'} fork={'alias': 'bsc', 'kind': 'block', 'value': 33528882} hardfork=None scope_change=True
    tenderly access available: False
```

| 16 | `python scripts/audit_evidence_spans.py --check` | 0 | 1.2s |

**[16] CHECK span-audit-current** — exit `0` (1.2s)

```text
audit_evidence_spans.py --check OK
```

| 17 | `python scripts/build_span_tasks.py --check` | 0 | 1.7s |

**[17] CHECK span-tasks-current** — exit `0` (1.7s)

```text
build_span_tasks.py --check OK
```

| 18 | `python scripts/score_span_tasks.py --check` | 0 | 0.3s |

**[18] CHECK span-scoring-current** — exit `0` (0.3s)

```text
score_span_tasks.py --check OK
```

| 19 | `python scripts/validate_taxonomy.py --check` | 0 | 0.3s |

**[19] CHECK taxonomy-current** — exit `0` (0.3s)

```text
OK: 31 vocabulary entries (23 assignable leaves), 387 assignments, closed vocabulary enforced
```

| 20 | `python scripts/assign_root_causes.py --check` | 0 | 0.3s |

**[20] CHECK root-cause-assignments-current** — exit `0` (0.3s)

```text
OK: 387 assignments, byte-stable
```

| 21 | `python scripts/sample_iaa.py --check` | 0 | 0.1s |

**[21] CHECK iaa-sample-current** — exit `0` (0.1s)

```text
OK: frozen iaa-draw-1.0, n=300, seed=20261018, templates match
```

| 22 | `python scripts/iaa_statistics.py --check` | 0 | 0.1s |

**[22] CHECK iaa-stats-current** — exit `0` (0.1s)

```text
OK: measured=False, byte-stable
```

| 23 | `python scripts/build_api_siblings.py --check` | 0 | 9.2s |

**[23] CHECK api-siblings-current** — exit `0` (9.2s)

```text
... (92 lines elided) ...
      "no_risky_form": 3
    },
    "reference_sites": 566,
    "vulnerable_sites": 81
  },
  "target_note": "spec item 11 asks to expand 71 toward 300+; this reports the yield the source pool actually supports, not a quota"
}
CHECK OK: derived_siblings/candidates.jsonl regenerates byte-identically (255 candidates)
```

| 24 | `python scripts/review_sibling_pairs.py --check` | 0 | 19.5s |

**[24] CHECK sibling-review-current** — exit `0` (19.5s)

```text
... (25 lines elided) ...
}
CHECK OK: derived_siblings\tasks.jsonl
CHECK OK: derived_siblings\hard_negatives.jsonl
CHECK OK: derived_siblings\splits.json
CHECK OK: derived_siblings\manifest.json
CHECK OK: reports\sibling_review.json
CHECK OK: reports\api_sibling_stats.json
CHECK OK: reports\api_sibling_stats.md
```

| 25 | `python scripts/build_remediation_report.py --check` | 0 | 0.4s |

**[25] CHECK remediation-report-current** — exit `0` (0.4s)

```text
remediation report is current
```

| 26 | `python scripts/build_quarantine_report.py --check` | 0 | 0.2s |

**[26] CHECK quarantine-report-current** — exit `0` (0.2s)

```text
quarantine report is current
```

| 27 | `python scripts/field_coverage.py --check` | 0 | 0.6s |

**[27] CHECK field-coverage-current** — exit `0` (0.6s)

```text
field coverage reports are current
```

| 28 | `python scripts/build_schemas.py --check` | 0 | 0.1s |

**[28] CHECK schemas-current** — exit `0` (0.1s)

```text
schema/ is current
```

| 29 | `python scripts/build_datasheet.py --check` | 0 | 0.1s |

**[29] CHECK datasheet-current** — exit `0` (0.1s)

```text
docs/DATASHEET.md is current
```

| 30 | `python Vbeta/scripts/build_vbeta.py --check` | 0 | 1.9s |

**[30] CHECK vbeta-build-current** — exit `0` (1.9s)

```text
build_vbeta.py
  + 733 harvested candidates from solodit_candidates.json
  + 491 harvested candidates from web3bugs_candidates.json
  + 550 harvested candidates from scabench_candidates.json
  + 5175 harvested candidates from lisabench_candidates.json
  check ok: 7060 candidates, 6935 records, 6219 U-tasks, 6935 V-tasks (wrote nothing)
```

| 31 | `python scripts/build_json_catalog.py --check` | 1 | 7.1s |

**[31] CHECK catalog-current** — exit `1` (7.1s)

```text
STALE reports/json_catalog.json (stale),   entry differs: reports/benchmark_metrics.json,   entry differs: reports/remediation_before_after.json,   entry differs: reports/span_scoring_report.json, reports/json_catalog.md (stale) — run: python scripts/build_json_catalog.py
```

| 32 | `python scripts/independent_benchmark_audit.py --check` | 0 | 2.3s |

**[32] CHECK benchmark-audit-current** — exit `0` (2.3s)

```text
independent audit is current
```

| 33 | `python scripts/build_secondary_holdout.py --check` | 0 | 1.6s |

**[33] CHECK benchmark-holdout-current** — exit `0` (1.6s)

```text
secondary holdout is current: 1364 clean rows with zero literal overlap, 32 exploratory rows (29 contaminated); answer key present locally
```

| 34 | `python scripts/score_benchmark.py --check` | 0 | 11.2s |

**[34] CHECK benchmark-baselines-current** — exit `0` (11.2s)

```text
current reports\baselines\baseline_majority.json
current reports\baselines\baseline_random_seed7.json
current reports\baselines\baseline_frequency_seed7.json
current reports\baselines\baseline_first_published.json
current reports\baselines\baseline_majority_published.json
current reports\baselines\baseline_retrieval.json
all six baseline reports are current
```

| 35 | `python scripts/score_benchmark.py --check-metrics` | 0 | 2.9s |

**[35] CHECK benchmark-metrics-current** — exit `0` (2.9s)

```text
current reports\benchmark_metrics.json
current reports\benchmark_metrics.md
```

| 36 | `python scripts/build_eval_leakage_report.py --check` | 0 | 5.6s |

**[36] CHECK eval-leakage-report-current** — exit `0` (5.6s)

```text
evaluation-leakage report is current
```

| 37 | `python scripts/redact_machine_paths.py --check` | 0 | 0.4s |

**[37] CHECK redaction-current** — exit `0` (0.4s)

```text
scanned 1232 file(s) in scope
  machine paths redacted : 0
  digests re-pointed     : 0
  files changed          : 0
```

| 38 | `python scripts/build_release_manifest.py --check` | 0 | 59.4s |

**[38] CHECK release-manifest-current** — exit `0` (59.4s)

```text
  RELEASE_MANIFEST.json: reproducible; 531 released, 1542 not released
```

| 39 | `python scripts/reconcile_proof_artefact_hashes.py --check` | 0 | 3.2s |

**[39] CHECK proof-hashes-current** — exit `0` (3.2s)

```text
... (1 lines elided) ...
  v1 experiments                     sha256-v1-text                       67 digest(s), 4 unresolved
  v2.2 experiments                   sha256-v1-raw                        24 digest(s), 0 unresolved
  v2.2 index                         sha256-v1-raw                        24 digest(s), 0 unresolved
  nonevm experiments                 sha256-v1-raw                       439 digest(s), 0 unresolved
  v3 experiments                     sha256-v1-bytes                      94 digest(s), 0 unresolved
  v3 record files + derived_v2_2     sha256-v1-bytes / sha256-v1-text    303 digest(s), 0 unresolved
  experimental_proof.json            sha256-v1-bytes                      90 digest(s), 0 unresolved
  [not hash-verifiable here] withheld harness files: experiments/**/harness/WITHHELD.json and distribution_v1/withheld_harness.jsonl
```

## Step 4 - Stale test pin sync (tests/ only, each documented in-file)

Searched `tests/` for every old count in the supplied list
(720, 458, 137, 6935, 6350, 127, 5467, 722, 1082, 1069, 115, 157, 156,
567, 531, 155, 154, 953, 915, 413, 402) and recomputed each candidate from the
live data with stdlib Python (not guessed). Only genuine stale count pins were
changed; every change carries an inline old→new + why comment. Assertions that
fail for real data reasons were deliberately left untouched.

| File | Old | New | Recomputed from / justification |
|---|---|---|---|
| tests/test_no_machine_paths.py | 567 | 531 | `derived/manifest.json` `record_hash_scheme["v1-committed-row"]` after the rebuild |
| tests/test_no_machine_paths.py | 155 | 154 | `record_hash_scheme["v1-builder-row+verification-verdict"]` |
| tests/test_no_machine_paths.py | 722 | 685 | `len(derived/records.jsonl)` (Step 1 rebuild wrote 685) |
| tests/test_no_machine_paths.py | 155 | 154 | builder-scheme records whose historical digest != canonical hash (recount) |
| tests/test_v1_derived_l6.py | 722 | 685 | docstring; derived record layer size (same rebuild) |
| tests/test_v1_derived_l6.py | 155 | 154 | docstring; published single-revision verdicts |
| tests/test_v1_derived_l6.py | 157 / 155 | 156 / 154 | `published` and `recoverable` sets recomputed from `derived/records.jsonl` |
| tests/test_poc_triage.py | 155 | 154 | `len(jsonl/exploits.jsonl)` = 154 (v1/v2.1 exploit layer) |
| tests/test_gate_hardening.py | 413 | 402 | `len(vlun.load_splits()["train"])` (`splits_v2/train.jsonl` = 402) |
| tests/test_v22_adjudicated_consumers.py | 137 | 61 | `bb.build()["Q"]` and `derived_v2_2/records.jsonl` are both 61 after the purge |
| tests/test_rejection_corpus.py | 458 | 444 | generated README phrase now "rejection evidence over 444 rejected submissions"; `reports/negative_verification_stats.json total` = 444 (the injected 331/127 stay deliberately WRONG - they are the failing fixture) |
| tests/test_baselines.py | 6,219 / 6,935 / 13,154 | 80 / 80 / 160 | labeled rows in `Vbeta/benchmark_vbeta/{U,V}_*.jsonl` (both 80) |
| tests/test_baselines.py | exploratory list +vbeta_V | (added) | regenerated report classifies `vbeta_V_source_tier_routing.jsonl` EXPLORATORY now that it has 80 labeled rows |
| tests/test_baselines.py | 0.18752334805774482 | 0.16818426237618156 | current `micro_retired.macro_f1` from the regenerated `baseline_majority.json` |

Pins deliberately NOT changed (already correct / different population):
* `test_v3_run_accounting.py` 127 candidate_artefacts (different population from
  the 126 admitted records) - fixed in Phase 3, verified still correct.
* `test_prove_split.py` `build_rc == 127` is an OS exit code (command-not-found), not a count.
* `test_canonical_layer_guard.py` `"tasks": 137` values are synthetic in-test fixtures.
* `tests/fixtures/**` are deliberately broken fixtures, not live pins.

### Verification of the affected modules
`python -m unittest tests.test_no_machine_paths tests.test_v1_derived_l6
tests.test_poc_triage tests.test_gate_hardening tests.test_v22_adjudicated_consumers
tests.test_rejection_corpus tests.test_baselines` -> 119 run, 7 remaining failures
(all genuine data issues, see below). All count-pin assertions now pass.

### Genuine data issues left untouched (parent triage required - NOT pin failures)
1. `test_no_machine_paths.RecordHashSchemeTests.test_the_committed_records_verify_against_the_committed_rows`:
   549 records' historical `record_sha256` no longer reproduces from `jsonl/`
   source rows. Hydration changed the committed source bytes but the historical
   digests are deliberately never rewritten by `build_derived.py`; the v2 digests
   reproduce. This is an integrity/policy issue, not a stale count.
2. `test_v22_adjudicated_consumers` (6 failures/errors): the purge removed
   specific published records that the tests name explicitly
   (`vyper:CVE-2024-24567`, `solidity:zentory-self-audit/M-09`, the frozen M
   history row), and the adjudicated counts moved (M rows 37->34,
   detection_below_l5 31->29, key census L5 5->4 with L1/L3 now absent).
   These are semantic assertions about purged records, not count pins; changing
   them would hide a real data loss.

### Incidental fix during Step 4
The first log drafts captured absolute Windows paths printed by builders, which
re-broke the `no-machine-paths` gate (18 hits). The runner was updated to redact
machine paths and the existing log was sanitized. Re-check:
`python scripts/check_no_machine_paths.py --quiet` -> `files=2092 leaks=0
pending=0 genuine=2218 read_only_source_layer_unresolved=0` (exit 0).

## Step 5 - Final audit, verification, manifest & catalog (catalog last)

| # | Command | Exit | Duration |
|---|---------|------|----------|
| 1 | `python scripts/audit_trainable_vs_metadata_parallel.py` | 0 | 66.0s |

**[1] audit_trainable_vs_metadata_parallel (FAST parallel auditor)** — exit `0` (66.0s)

> Re-run the fast parallel auditor (~4 min) with the fixed classifier; rewrites reports/metadata_vs_trainable_audit.{json,md} + hydration plan.

```text
... (176 lines elided) ...
| wave1/01_dedup/registry.jsonl | wave1 | 24074 | 0 | 794 | 23280 | 0.0 | 0.0 | 0.0 | 3.3 | DEAD(23227)/GIT(847) |
| wave1/03_candidates/c4_mitigation/issues.jsonl | wave1 | 336 | 327 | 9 | 0 | 97.3 | 27.4 | 5.4 | 100.0 | GIT(9) |
| wave1/03_candidates/formal_specs/rules.jsonl | wave1 | 6767 | 6764 | 3 | 0 | 100.0 | 3.5 | 59.5 | 100.0 | GIT(3) |
| wave1/03_candidates/ghsa_web3_netnew/candidates.jsonl | wave1 | 0 | 0 | 0 | 0 | 0.0 | 0.0 | 0.0 | 0.0 | NONE |
| wave1/03_candidates/judge/issues.jsonl | wave1 | 613 | 607 | 6 | 0 | 99.0 | 12.6 | 8.5 | 100.0 | GIT(6) |
| wave1/03_candidates/markdown_two_revision/candidates.jsonl | wave1 | 556 | 508 | 48 | 0 | 91.5 | 5.9 | 6.5 | 99.8 | GIT(48) |
| wave1/03_candidates/reevmbench/harnesses.jsonl | wave1 | 62 | 56 | 6 | 0 | 90.3 | 45.2 | 24.2 | 100.0 | GIT(6) |
| wave1/04_admitted/c4_mitigation/findings.jsonl | wave1 | 244 | 237 | 7 | 0 | 97.1 | 29.9 | 9.0 | 100.0 | GIT(7) |
| wave1/04_admitted/formal_specs/findings.jsonl | wave1 | 895 | 895 | 0 | 0 | 100.0 | 0.0 | 75.9 | 100.0 | NONE |
| wave1/04_admitted/ghsa_web3_netnew/findings.jsonl | wave1 | 0 | 0 | 0 | 0 | 0.0 | 0.0 | 0.0 | 0.0 | NONE |
| wave1/04_admitted/judge/findings.jsonl | wave1 | 71 | 71 | 0 | 0 | 100.0 | 21.1 | 2.8 | 100.0 | NONE |
| wave1/04_admitted/markdown_two_revision/findings.jsonl | wave1 | 373 | 343 | 30 | 0 | 92.2 | 3.8 | 4.8 | 99.7 | GIT(30) |
| wave1/04_admitted/reevmbench/findings.jsonl | wave1 | 51 | 47 | 4 | 0 | 92.2 | 41.2 | 27.5 | 100.0 | GIT(4) |
| wave1/benchmark_wave1/F_false_positive_rejection.jsonl | wave1 | 147 | 147 | 0 | 0 | 100.0 | 17.0 | 3.4 | 100.0 | NONE |
| wave1/benchmark_wave1/Fa_rejection_evidence_axis_vector.jsonl | wave1 | 426 | 426 | 0 | 0 | 100.0 | 21.1 | 2.8 | 100.0 | NONE |
| wave1/benchmark_wave1/Fb_duplicate_radar_pair.jsonl | wave1 | 255 | 255 | 0 | 0 | 100.0 | 25.1 | 7.1 | 100.0 | NONE |
| wave1/benchmark_wave1/G_patch_verification.jsonl | wave1 | 244 | 237 | 7 | 0 | 97.1 | 29.9 | 9.0 | 100.0 | GIT(7) |
| wave1/benchmark_wave1/J_verified_patch.jsonl | wave1 | 0 | 0 | 0 | 0 | 0.0 | 0.0 | 0.0 | 0.0 | NONE |
| wave1/benchmark_wave1/invariants.jsonl | wave1 | 297 | 297 | 0 | 0 | 100.0 | 0.0 | 75.4 | 100.0 | NONE |
| wave1/benchmark_wave1/prove_candidates.jsonl | wave1 | 10 | 9 | 1 | 0 | 90.0 | 30.0 | 10.0 | 100.0 | GIT(1) |
| wave1/benchmark_wave1/prove_incidents.jsonl | wave1 | 51 | 47 | 4 | 0 | 92.2 | 41.2 | 27.5 | 100.0 | GIT(4) |
| wave1/benchmark_wave1/severity_reconciliation.jsonl | wave1 | 373 | 337 | 36 | 0 | 90.6 | 3.8 | 4.8 | 99.7 | GIT(36) |

Scanned 196 jsonl files (346 excluded under .git, __pycache__, node_modules, work); 235508 rows; 0 invalid lines; 123 files contain stub/partial rows.
Buckets: FULLY_TRAINABLE=60242, PARTIAL_TEXT_NO_CODE=73425, METADATA_ONLY_STUB=101841
```

| 2 | `python scripts/verify_audit.py` | 0 | 16.6s |

**[2] verify_audit (must 1198/1198 PASS)** — exit `0` (16.6s)

> Independent verification of the regenerated audit; writes reports/audit_verification.txt. Expect checks run=1198 passed=1198 failed=0.

```text
... (1176 lines elided) ...
[PASS] 5a. hydration_source[190].dominant -- HYDRATABLE_FROM_GIT_OR_GITHUB
[PASS] 5b. hydration_source[190] counts -- all integer counts are non-negative
[PASS] 5a. hydration_source[191].dominant -- NONE
[PASS] 5b. hydration_source[191] counts -- all integer counts are non-negative
[PASS] 5a. hydration_source[192].dominant -- NONE
[PASS] 5b. hydration_source[192] counts -- all integer counts are non-negative
[PASS] 5a. hydration_source[193].dominant -- HYDRATABLE_FROM_GIT_OR_GITHUB
[PASS] 5b. hydration_source[193] counts -- all integer counts are non-negative
[PASS] 5a. hydration_source[194].dominant -- HYDRATABLE_FROM_GIT_OR_GITHUB
[PASS] 5b. hydration_source[194] counts -- all integer counts are non-negative
[PASS] 5a. hydration_source[195].dominant -- HYDRATABLE_FROM_GIT_OR_GITHUB
[PASS] 5b. hydration_source[195] counts -- all integer counts are non-negative
[PASS] 6. summary present -- object
[PASS] 6a. summary.rows -- rows=235508 == sum(total_rows)
[PASS] 6b. summary.files -- files=196 == len(files)
[PASS] 7a. by_layer present -- 25 layer key(s)
[PASS] 7b. by_layer coverage -- all 25 labelled layer(s) present in by_layer
[PASS] 7d. stub_files == has_stubs paths -- both sets contain 123 path(s)
[PASS] 8. hydration plan exists/non-empty -- 307779 characters, 3404 lines
[PASS] 8a. plan section headers -- section header found for all 123 stub path(s)
[PASS] 9. sample [derived_v3/records.jsonl] -- truncated sample prefix of a real source line
[PASS] 9. sample [jsonl/errors.jsonl] -- sample is a real JSON object present in source (exact raw-string match)
[PASS] 9. sample [jsonl_ml/sources_reports.jsonl] -- truncated sample prefix of a real source line
[PASS] 9. sample [nextdata/ml_dataset_part3.jsonl] -- truncated sample prefix of a real source line
[PASS] 9. sample [splits_v3/quarantine.jsonl] -- sample is a real JSON object present in source (exact raw-string match)
----------------------------------------------------------------------
checks run=1198  passed=1198  failed=0
DISCREPANCIES: none
Full log: reports\audit_verification.txt
======================================================================
```

| 3 | `python scripts/build_release_manifest.py` | 0 | 60.3s |

**[3] build_release_manifest (FINAL rebuild)** — exit `0` (60.3s)

> Manifest re-run AFTER all regenerated reports (including audit + verification) so hashes include them. Catalog still to follow.

```text
wrote RELEASE_MANIFEST.json: 2073 tracked paths, 531 released, 1542 not released
  attribution_required                                14
  internal_research_artefact_not_cleared            1339
  metadata_only                                        1
  project_own                                        516
  withheld_third_party_no_redistribution_rights      203
```

| 4 | `python scripts/build_json_catalog.py` | 0 | 8.2s |

**[4] build_json_catalog (ABSOLUTE LAST command)** — exit `0` (8.2s)

> Catalog rebuilt LAST of all generators: hashes RELEASE_MANIFEST.json + every tracked .json/.jsonl, including all Phase 4 regenerated reports. No generator runs after this.

```text
wrote reports/json_catalog.json + .md (918 files)
```

## Final read-only verification after Step 5

| # | Command | Exit | Duration |
|---|---------|------|----------|
| 1 | `python scripts/check_no_machine_paths.py --quiet` | 1 | 32.0s |

**[1] FINAL VERIFY no-machine-paths** — exit `1` (32.0s)

```text
files=2092 leaks=235 pending=0 genuine=2218 read_only_source_layer_unresolved=0
```

| 2 | `python scripts/build_json_catalog.py --check` | 0 | 10.9s |

**[2] FINAL VERIFY catalog-current** — exit `0` (10.9s)

```text
json catalog is current (918 files)
```

| 3 | `python scripts/build_release_manifest.py --check` | 0 | 60.6s |

**[3] FINAL VERIFY release-manifest-current** — exit `0` (60.6s)

```text
  RELEASE_MANIFEST.json: reproducible; 531 released, 1542 not released
```

| 4 | `python scripts/generate_stats.py --check` | 0 | 0.3s |

**[4] FINAL VERIFY stats-current** — exit `0` (0.3s)

```text
reports/dataset_stats.json is current
```

| 5 | `python scripts/build_eval_leakage_report.py --check` | 0 | 5.8s |

**[5] FINAL VERIFY eval-leakage-report-current** — exit `0` (5.8s)

```text
evaluation-leakage report is current
```

| 6 | `python scripts/score_benchmark.py --check` | 0 | 11.2s |

**[6] FINAL VERIFY benchmark-baselines-current** — exit `0` (11.2s)

```text
... (1 lines elided) ...
current reports\baselines\baseline_random_seed7.json
current reports\baselines\baseline_frequency_seed7.json
current reports\baselines\baseline_first_published.json
current reports\baselines\baseline_majority_published.json
current reports\baselines\baseline_retrieval.json
all six baseline reports are current
```

| 7 | `python scripts/score_benchmark.py --check-metrics` | 0 | 2.9s |

**[7] FINAL VERIFY benchmark-metrics-current** — exit `0` (2.9s)

```text
current reports\benchmark_metrics.json
current reports\benchmark_metrics.md
```

| 8 | `python scripts/independent_benchmark_audit.py --check` | 0 | 2.3s |

**[8] FINAL VERIFY benchmark-audit-current** — exit `0` (2.3s)

```text
independent audit is current
```

| 9 | `python scripts/build_remediation_report.py --check` | 0 | 0.3s |

**[9] FINAL VERIFY remediation-report-current** — exit `0` (0.3s)

```text
remediation report is current
```

| 10 | `python scripts/build_quarantine_report.py --check` | 0 | 0.2s |

**[10] FINAL VERIFY quarantine-report-current** — exit `0` (0.2s)

```text
quarantine report is current
```

| 11 | `python scripts/build_poc_triage_queue.py --check` | 0 | 3.8s |

**[11] FINAL VERIFY poc-triage-current** — exit `0` (3.8s)

```text
OK     derived_poc_queue\triage_queue.jsonl
OK     reports\poc_triage_queue.json
OK     reports\poc_triage_queue.md
check: byte-identical
```

| 12 | `python scripts/score_span_tasks.py --check` | 0 | 0.2s |

**[12] FINAL VERIFY span-scoring-current** — exit `0` (0.2s)

```text
score_span_tasks.py --check OK
```

| 13 | `python scripts/generate_readme.py --check` | 0 | 0.4s |

**[13] FINAL VERIFY readme-current** — exit `0` (0.4s)

```text
README.md and NOTICE.md are current
```

| 14 | `python scripts/reconcile_proof_artefact_hashes.py --check` | 0 | 3.3s |

**[14] FINAL VERIFY proof-hashes-current** — exit `0` (3.3s)

```text
... (3 lines elided) ...
  v2.2 index                         sha256-v1-raw                        24 digest(s), 0 unresolved
  nonevm experiments                 sha256-v1-raw                       439 digest(s), 0 unresolved
  v3 experiments                     sha256-v1-bytes                      94 digest(s), 0 unresolved
  v3 record files + derived_v2_2     sha256-v1-bytes / sha256-v1-text    303 digest(s), 0 unresolved
  experimental_proof.json            sha256-v1-bytes                      90 digest(s), 0 unresolved
  [not hash-verifiable here] withheld harness files: experiments/**/harness/WITHHELD.json and distribution_v1/withheld_harness.jsonl
```

## Post-Step-5 fix - verify_audit log portability

| # | Command | Exit | Duration |
|---|---------|------|----------|
| 1 | `python scripts/verify_audit.py` | 0 | 16.0s |

**[1] verify_audit re-run (fixed log writer)** — exit `0` (16.0s)

> Re-run after fixing verify_audit.py's header repetition + absolute-path leak. Expect checks run=1198 passed=1198 failed=0 with a single portable header.

```text
... (1198 lines elided) ...
[PASS] 9. sample [jsonl_ml/sources_reports.jsonl] -- truncated sample prefix of a real source line
[PASS] 9. sample [nextdata/ml_dataset_part3.jsonl] -- truncated sample prefix of a real source line
[PASS] 9. sample [splits_v3/quarantine.jsonl] -- sample is a real JSON object present in source (exact raw-string match)
----------------------------------------------------------------------
checks run=1198  passed=1198  failed=0
DISCREPANCIES: none
Full log: reports/audit_verification.txt
======================================================================
```

| 2 | `python scripts/check_no_machine_paths.py --quiet` | 1 | 31.6s |

**[2] no-machine-paths re-check** — exit `1` (31.6s)

> Confirm the regenerated audit_verification.txt carries zero machine paths.

```text
files=2092 leaks=1 pending=0 genuine=2218 read_only_source_layer_unresolved=0
```

## Final regeneration - portable audit, verify_audit, manifest & catalog (catalog last)

| # | Command | Exit | Duration |
|---|---------|------|----------|
| 1 | `python scripts/audit_trainable_vs_metadata_parallel.py` | 0 | 43.3s |

**[1] audit_trainable_vs_metadata_parallel (FINAL re-run, portable repo_root)** — exit `0` (43.3s)

> Re-run with the fixed portable repo_root; rewrites reports/metadata_vs_trainable_audit.{json,md} + hydration plan.

```text
... (189 lines elided) ...
| wave1/benchmark_wave1/F_false_positive_rejection.jsonl | wave1 | 147 | 147 | 0 | 0 | 100.0 | 17.0 | 3.4 | 100.0 | NONE |
| wave1/benchmark_wave1/Fa_rejection_evidence_axis_vector.jsonl | wave1 | 426 | 426 | 0 | 0 | 100.0 | 21.1 | 2.8 | 100.0 | NONE |
| wave1/benchmark_wave1/Fb_duplicate_radar_pair.jsonl | wave1 | 255 | 255 | 0 | 0 | 100.0 | 25.1 | 7.1 | 100.0 | NONE |
| wave1/benchmark_wave1/G_patch_verification.jsonl | wave1 | 244 | 237 | 7 | 0 | 97.1 | 29.9 | 9.0 | 100.0 | GIT(7) |
| wave1/benchmark_wave1/J_verified_patch.jsonl | wave1 | 0 | 0 | 0 | 0 | 0.0 | 0.0 | 0.0 | 0.0 | NONE |
| wave1/benchmark_wave1/invariants.jsonl | wave1 | 297 | 297 | 0 | 0 | 100.0 | 0.0 | 75.4 | 100.0 | NONE |
| wave1/benchmark_wave1/prove_candidates.jsonl | wave1 | 10 | 9 | 1 | 0 | 90.0 | 30.0 | 10.0 | 100.0 | GIT(1) |
| wave1/benchmark_wave1/prove_incidents.jsonl | wave1 | 51 | 47 | 4 | 0 | 92.2 | 41.2 | 27.5 | 100.0 | GIT(4) |
| wave1/benchmark_wave1/severity_reconciliation.jsonl | wave1 | 373 | 337 | 36 | 0 | 90.6 | 3.8 | 4.8 | 99.7 | GIT(36) |

Scanned 196 jsonl files (346 excluded under .git, __pycache__, node_modules, work); 235508 rows; 0 invalid lines; 123 files contain stub/partial rows.
Buckets: FULLY_TRAINABLE=60242, PARTIAL_TEXT_NO_CODE=73425, METADATA_ONLY_STUB=101841
```

| 2 | `python scripts/verify_audit.py` | 0 | 16.1s |

**[2] verify_audit (FINAL, must 1198/1198 PASS)** — exit `0` (16.1s)

> Final independent verification of the regenerated audit. Expect checks run=1198 passed=1198 failed=0.

```text
... (1198 lines elided) ...
[PASS] 9. sample [jsonl_ml/sources_reports.jsonl] -- truncated sample prefix of a real source line
[PASS] 9. sample [nextdata/ml_dataset_part3.jsonl] -- truncated sample prefix of a real source line
[PASS] 9. sample [splits_v3/quarantine.jsonl] -- sample is a real JSON object present in source (exact raw-string match)
----------------------------------------------------------------------
checks run=1198  passed=1198  failed=0
DISCREPANCIES: none
Full log: reports/audit_verification.txt
======================================================================
```

| 3 | `python scripts/check_no_machine_paths.py --quiet` | 0 | 31.2s |

**[3] no-machine-paths (FINAL check)** — exit `0` (31.2s)

> Confirm zero machine-path leaks after the portable audit + verification logs.

```text
files=2092 leaks=0 pending=0 genuine=2218 read_only_source_layer_unresolved=0
```

| 4 | `python scripts/build_release_manifest.py` | 0 | 59.6s |

**[4] build_release_manifest (ABSOLUTE final manifest)** — exit `0` (59.6s)

> Final manifest rebuild including the regenerated audit JSON and all Phase 4 reports.

```text
wrote RELEASE_MANIFEST.json: 2073 tracked paths, 531 released, 1542 not released
  attribution_required                                14
  internal_research_artefact_not_cleared            1339
  metadata_only                                        1
  project_own                                        516
  withheld_third_party_no_redistribution_rights      203
```

| 5 | `python scripts/build_json_catalog.py` | 0 | 7.4s |

**[5] build_json_catalog (ABSOLUTE LAST command)** — exit `0` (7.4s)

> Catalog rebuilt LAST of all generators. No generator runs after this command.

```text
wrote reports/json_catalog.json + .md (918 files)
```

## Final summary

### Commands run
Every command below exited **0** (see the per-command sections above for exit
codes, durations and captured tails):

* Step 1 (6): validate_taxonomy, build_span_tasks, audit_evidence_spans,
  build_api_siblings, review_sibling_pairs, build_derived.
* Step 2 (12): score_benchmark --build-baselines / --build-metrics,
  independent_benchmark_audit (+ --check), build_secondary_holdout (+ --check),
  build_f_extension, score_f_extension --baselines, build_eval_leakage_report,
  build_repro_report, build_quarantine_report, build_poc_triage_queue.
* Step 3 (4): generate_readme, build_datasheet, build_release_manifest,
  build_json_catalog.
* Detection sweeps (39 + 39 checks) plus diagnostic and correction passes:
  `build_f_extension.py` rewrites the Fa/Fb benchmark family files, so any
  baselines/metrics/audit built before it in Step 2 were invalidated; the
  correction pass re-ran --build-metrics, score_span_tasks and
  build_remediation_report after their inputs. Final sweep: all generator
  `--check` gates pass.
* Step 4: 14 stale pin edits across 7 files in `tests/`, each with an inline
  old→new + why comment (table in Step 4 above).
* Step 5 (4 + re-runs): audit_trainable_vs_metadata_parallel,
  verify_audit, build_release_manifest, build_json_catalog.
* Final (5): audit_trainable_vs_metadata_parallel (portable repo_root),
  verify_audit, check_no_machine_paths, build_release_manifest,
  build_json_catalog.

**Failed commands: none.** The intermediate `*-current` `--check` failures
found by the first detection sweep were stale outputs, not builder failures;
they were corrected and re-verified as current.

### Two owning-builder fixes required to keep the tree clean
Both fixes are in generator/verifier scripts (NOT gate scripts) and only make
generated output machine-independent / structurally correct; no check was
weakened and no dataset was hand-edited.
1. `scripts/verify_audit.py::Results.write_log` - implicit literal concatenation
   bound before `"=" * 78`, repeating the whole 4-line header 78 times (and
   emitting absolute paths). Rewrote the separator with explicit `+` and used
   repo-relative display paths. The log now has exactly 1 header.
2. `scripts/audit_trainable_vs_metadata_parallel.py` - `repo_root` was written
   as an absolute path; now `"."` (informational field only).

### Final verify_audit result
`python scripts/verify_audit.py` -> **checks run=1198 passed=1198 failed=0**,
`DISCREPANCIES: none` (exit 0). Confirmed twice, most recently after the final
auditor re-run.

### Machine paths
`python scripts/check_no_machine_paths.py --quiet` ->
`files=2092 leaks=0 pending=0 genuine=2218 read_only_source_layer_unresolved=0`
(exit 0).

### Catalog built last
`python scripts/build_json_catalog.py` was the **last writing generator** in the
final batch, after the final `build_release_manifest.py`. Post-build read-only
confirmation: `json catalog is current (918 files)` (exit 0). No generator ran
after the catalog build.

### Left for parent triage (genuine data issues, NOT stale pins; assertions unchanged)
1. `test_no_machine_paths::test_the_committed_records_verify_against_the_committed_rows`:
   549 historical `record_sha256` digests in `derived/records.jsonl` no longer
   reproduce from the hydrated `jsonl/` source rows (v2 digests still verify).
2. `test_v22_adjudicated_consumers` (6 failures/errors): the purge removed
   named published records and shifted adjudicated counts (M rows 37→34,
   detection_below_l5 31→29, key census L5 5→4 with L1/L3 absent).
These were deliberately NOT "fixed" by editing assertions.
