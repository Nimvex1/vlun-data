# ANSWER_KEY.md — what every benchmark answer key means

Each benchmark task carries an answer key built from its source record.
This file defines the schema per family, what `answer_key_status` means,
and which families are exactly scorable. The scorer is
`scripts/score_benchmark.py`; its per-family projections are defined there
and restated here. Anything here that disagrees with the task files is a
bug — the files win, this doc gets fixed.

## Status vocabulary (every task has one)

| status | meaning |
|---|---|
| `labeled` | the answer exists in the source record; task is scorable |
| `partial` | the answer exists but is incomplete/hedged; excluded from exact-match scoring |
| `unlabeled` | no answer exists in the source record; excluded |
| `unscorable` | answered but not machine-checkable in this harness; excluded |

Only `labeled` tasks are scored. Coverage (predicted ÷ scorable) is reported
alongside accuracy so abstention is visible, never silent.

## Per-family keys (exactly-scorable scalar in bold)

| Family | Key field | Values observed |
|---|---|---|
| A_vulnerability_detection | **label** | vulnerable / no_confirmed_vulnerability (720) |
| C_attacker_reasoning | **attacker_kind** | unprivileged / privileged / malicious_dependency / honest_but_misconfigured (290 labeled) |
| E_exploit_verification | **verdict** | passes / fails (7) |
| F_false_positive_rejection | **label** | valid / invalid (17) |
| I_verified_non_exploit | **label** | exploitable / not_exploitable (1 labeled, 2 unscorable) |
| J_verified_patch | **label** | effective + both-leg forge results (7) |
| K_language_ecosystem_routing | **language** | solidity / vyper / rust / move / cairo (137) |
| L_severity_reconciliation | **severity** | critical / high / medium / low / informational / unknown (128 labeled) |
| M_experiment_level_classification | **level** | L0–L6 + outcome (37, all experimentally backed) |
| N_attacker_identity_extraction | **actor_mentioned** | true / false (14 labeled) |
| O_record_class_and_scope | **record_class** | advisory / audit_finding / judged / … (137) |
| P_provenance_tier_and_rights | **highest_authority_tier** | 0 / 1 / 3 (137) |
| R_v3_source_tier_routing | **answer.tier** | 0 / 1 / 2 (5,467) |
| S_v3_contest_outcome | **answer.outcome** | finding / negative (1,072) |
| T_v31_taxonomy_explicit | **answer.vulnerability_class** | free-text class, explicit only (589) |
| U_vbeta_language_routing | **answer** | language string (673; unknown-language rows excluded by construction) |
| V_vbeta_source_tier_routing | **answer** | tier string (782) |

## Not exactly scorable (excluded with reason, not silently)

| Family | Reason |
|---|---|
| B_root_cause_reasoning | 0 labeled rows (416 partial, 304 unlabeled) |
| D_exploit_construction | generative (write the PoC test) — needs a judge |
| G_patch_verification | 0 labeled rows |
| H_verified_exploit | descriptive reference (behaviours, no label field) |
| Q_evidence_type_and_quality_rubric | judge-graded rubric dict (partial credit by definition) |

## Provenance of every key

- A–J keys rebuild from `jsonl/` + `experiments/` verdicts.
- K–Q keys rebuild from `derived_v2_2/records.jsonl`.
- R/S keys rebuild from `derived_v3/records.jsonl`; T from v3.1 preview rows.
- U/V keys rebuild from `Vbeta/derived_vbeta/records.jsonl`.
- `scripts/check_manifests.py` verifies every task resolves to its record.
