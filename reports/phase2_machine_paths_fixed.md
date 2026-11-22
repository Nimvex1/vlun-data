# Phase 2 — machine-path cleanup (final report)

Gate: `python scripts/check_no_machine_paths.py` (human-readable scan).
This file deliberately writes the operator account as `<user>` so it adds no
new machine-path hit of its own.

## Initial state (from the prior agent's scan)

| Category | Hits |
|---|---|
| `OPERATOR_LEAK` | 286 |
| `read_only_source_layer_unresolved` | 236 |
| **Total** | **522** |

The prior agent cleared 521 of the 522; this final cleanup cleared the last
one and re-ran the gate to confirm a clean result.

## Deleted scratch reports (19)

Backed up to `C:\Users\<user>\AppData\Local\Temp\opencode\vlun_phase2_backup\`
before removal from `reports/`:

1. `_audit_explore_prove_wave1_misc.md`
2. `_audit_explore_v1.md`
3. `_audit_explore_v22_v3.md`
4. `_audit_explore_vbeta_v4.md`
5. `_classifier_fix_notes.md`
6. `_gate_owner_notes.md`
7. `_parallel_audit_notes.md`
8. `_phase1_baseline_notes.md`
9. `_phase1_rights_eval_notes.md`
10. `_phase1_score_notes.md`
11. `_pytest_profile.txt`
12. `_recon_gates_validators.md`
13. `_recon_hydration_feasibility.md`
14. `_recon_pipeline_dependencies.md`
15. `_recon_sample_hydration_probes.md`
16. `_v1_hydration_log.md`
17. `_v22_v3_hydration_log.md`
18. `_vbeta_v4_hydration_log.md`
19. `_wave1_hydration_log.md`

In addition, the final cleanup step deleted `reports/_phase3_diagnosis.md`,
the last remaining operator leak (`windows_user_profile` on line 3). It was
backed up to the same directory first; the copy is byte-identical to the
removed file (SHA-256 verified). No committed deliverable was removed.

## Normalized files (10)

Paths were rewritten in place; the account component was either dropped (the
absolute checkout prefix became a repository-relative path) or replaced by the
repository's fixed `REDACTED` redaction token.

1. `reports/_final_gates.txt`
2. `reports/_pytest_final.txt`
3. `reports/audit_verification.txt`
4. `reports/metadata_stub_hydration_plan.md`
5. `reports/metadata_vs_trainable_audit.json`
6. `reports/metadata_vs_trainable_audit_before.json`
7. `jsonl_ml/findings_move.jsonl` — 1 unresolved hit cleared
8. `jsonl_ml/findings_reports.jsonl` — 223 unresolved hits cleared
9. `jsonl_ml/findings_vyper.jsonl` — 2 unresolved hits cleared
10. `jsonl_ml/sources_reports.jsonl` — 10 unresolved hits cleared

### Example path transformations

The `jsonl_ml/` counts above sum to the 236 `read_only_source_layer_unresolved`
hits recorded in the pre-fix scan report.

Absolute traceback/progress-log paths → repository-relative paths (forward
slashes), from the pre-normalization backups:

- `C:\Users\<user>\Downloads\vlun-data-main\vlun-data-main\Vbeta\tests\test_vbeta.py`
  → `Vbeta/tests/test_vbeta.py`
- `C:/Users/<user>/Downloads/vlun-data-main/vlun-data-main/derived_prove/candidate_ledger.jsonl`
  → `derived_prove/candidate_ledger.jsonl`
- `C:\Users\<user>\Downloads\vlun-data-main\vlun-data-main\training\canonical\detection.train.part-000.jsonl`
  → `training/canonical/detection.train.part-000.jsonl`
- `C:\Users\<user>\Downloads\vlun-data-main\vlun-data-main\reports\independent\audit.json`
  → `reports/independent/audit.json`

Pinned source-layer paths → account component replaced with the `REDACTED`
token (from `jsonl_ml/findings_reports.jsonl` and `jsonl_ml/sources_reports.jsonl`):

- `C:\\Users\\<user>\\Documents\\zentory-protocol-main\\report.md`
  → `C:\\Users\\REDACTED\\Documents\\zentory-protocol-main\\report.md`
- `C:\\Users\\<user>\\Downloads\\kerf-contracts-main\\kerf-contracts-main\\REPORT.md`
  → `C:\\Users\\REDACTED\\Downloads\\kerf-contracts-main\\kerf-contracts-main\\REPORT.md`

## Scan-report regeneration

`reports/machine_path_scan.json` was regenerated with its owning builder,
`python scripts/check_no_machine_paths.py --write-report`. The gate explicitly
excludes this ledger from its own scan, so regenerating it does not affect the
result below.

## Final checker output

```
scanned 2089 files
  operator leaks : 0
  pending        : 0
  genuine        : 2218
  read_only_source_layer_unresolved: 0
  read_only_source_layer_unresolved jsonl/: 0 hit(s)
  read_only_source_layer_unresolved jsonl_ml/: 0 hit(s)
  read_only_source_layer_unresolved jsonl_v3/: 0 hit(s)
```

Exit code: **0** (no `LEAK`, `PENDING`, or unresolved source-layer hits).

## Deferred

The release manifest and catalog were **not** rebuilt here; that is Phase 4
work and will be done after all data changes are complete.
