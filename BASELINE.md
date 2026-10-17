# BASELINE — frozen measurements at `e79b31a` (2026-10-13)

Read this before `_audit/INDEPENDENT_REVIEW.md`. The review targets `93af4b9`
(2026-10-04); this file records which of its findings still stand at HEAD,
re-measured from the canonical files — never quoted from prose.

- Commit: `e79b31a5b6b90189ac490137cc40f6eda508cea3` (`e79b31a`)
- Platform: Windows, Python 3.12.10
- Test suite: `python -m unittest discover -s tests` → **177 tests, OK**
- Gate runner: `python scripts/run_gates.py` → **22/22 PASS, 0 fail, 0 skipped**

## Gate checks: 374, 0 critical failures

From `reports/reproducibility_report.md` (sum of per-gate checks):

| Gate | Checks | Critical failures |
|---|---|---|
| v1 authorship (`scripts/validate.py`) | 72 | 0 |
| v3 (`scripts/validate_v3.py`) | 42 | 0 |
| v3.1 (`scripts/validate_v31.py`) | 44 | 0 |
| Vbeta (`Vbeta/scripts/validate_vbeta.py`) | 35 | 0 |
| cross-manifest (`scripts/check_manifests.py`) | 171 | 0 |
| reproducibility (`scripts/check_reproducibility.py`) | 19 | 0 |
| **Total** | **383** | **0** |

## Benchmark validity gap (§1-A): 15 scored families, 9 at exactly 1.0000

From `reports/independent/audit.json`
(`families[*].baselines_test_split.best_shortcut_accuracy`,
`families[*].answer_leakage.severity`). Re-measured 2026-10-13: exact match.

| best_shortcut | family | answer_leak |
|---|---|---|
| 1.0000 | B_root_cause_reasoning | none |
| 1.0000 | E_exploit_verification | medium |
| 1.0000 | K_language_ecosystem_routing | high |
| 1.0000 | M_experiment_level_classification | none |
| 1.0000 | N_attacker_identity_extraction | none |
| 1.0000 | O_record_class_and_scope | medium |
| 1.0000 | v3_R_source_tier_routing | none |
| 1.0000 | v3_S_contest_outcome | none |
| 1.0000 | v3_T_taxonomy_explicit | medium |
| 0.9998 | vbeta_V_source_tier_routing | none |
| 0.9834 | vbeta_U_language_routing | medium |
| 0.9032 | P_provenance_tier_and_rights | none |
| 0.5641 | C_attacker_reasoning | medium |
| 0.5510 | A_vulnerability_detection | none |
| 0.5172 | L_severity_reconciliation | high |

 Seven families report no shortcut score and are excluded from the count:
 D, F, G, H, I, J, Q. Two families leak literally at `high`: **K** and **L**.

## Empty depth fields (§1-B): 12,402 records × 4 fields at 0.0%

From `reports/field_coverage.md`. Re-measured 2026-10-13: exact match.

| Field | v3 (5,467) known | Vbeta (6,935) known |
|---|---|---|
| `attack_sequence` | 0 (0.0%) | 0 (0.0%) |
| `root_cause` | 0 (0.0%) | 0 (0.0%) |
| `impact` | 0 (0.0%) | 0 (0.0%) |
| `fix_description` | 0 (0.0%) | 0 (0.0%) |

Also: `vbeta.records.status_observed` 91/6,935 = **1.3%**,
`v1.findings.root_cause` 5/264 = **1.9%**.

## Evidence pointers (§1-C): 1,905 silent + 1,591 prose-attributed

Measured by walking every `{value, evidence_type, source_refs}` wrapper in
`derived/records.jsonl` (722 records) on 2026-10-13:

| evidence_type | key absent | empty list | with refs |
|---|---|---|---|
| `derived_fact` | 877 | 306 | 0 |
| `observed_fact` | 0 | 722 | 0 |
| `reported_claim` | 1,483 | 108 | 0 |
| `unknown` | 432 | 5,362 | 0 (correct — claims nothing) |

Zero wrappers of any type carry a non-empty `source_refs` in
`derived/records.jsonl`.

> **Correction to improve.md §1-C (operator-approved 2026-10-13):** the plan
> says `reported_claim 1591 (carries refs)`. It does not — all 1,591 lack
> `source_refs`. They are not unattributed: a sample shows prose attribution
> (`attributed_sentence`, `why`, `basis`, e.g.
> `attacker_model.attacker_identity`), but there is no machine-checkable
> pointer. Phase 1's gate scope is unchanged (`derived_fact`/`observed_fact`);
> the silent-pointer defect is **1,905** fields, with **1,591** further fields
> carrying prose attribution but no `source_refs`.

## Review status: all 8 refutations + 6 stale-claim rows already fixed

The six claims improve.md §0 lists as fixed were re-verified at `e79b31a`
(all hold; see the status table appended to
`_audit/INDEPENDENT_REVIEW.md`, body frozen). Machine-readable copy:
`reports/baseline/measured_2026-10-13.json`. Catalog entry for that JSON is
regenerated in the same commit (`reports/json_catalog.{json,md}`).

## Honest ceiling

Per improve.md §0: two workstreams are blocked on human actions (funded
Ethereum archive RPC key; outbound licence-clearance emails). Without them
the honest ceiling is **~8.5/10**, not 10/10.
