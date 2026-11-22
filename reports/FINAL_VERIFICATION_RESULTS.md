# Final Verification Results

Date: 2026-11-22
Repo: checkout root (Windows / PowerShell, Python 3.12.10, stdlib-only project scripts)
Scope: definitive, read-only verification of the now-stable state. All four suites were
run to completion, one at a time, followed by the catalog determinism proof. No failure
was fixed and no check was weakened. The only file written by this verification pass is
this report.

## Method

Each command was launched as a detached child process (`Start-Process -PassThru -WindowStyle
Hidden`, stdout/stderr redirected to scratch files outside the repo), awaited with a
process-handle wait (`Process.WaitForExit()`), and timed with a `Stopwatch`. No sleep-based
polling was used, and no second copy of a suite was started while one was running. The
wrapper did not surface a numeric child exit code, so the verdicts below are the suites'
own exact reported output.

Scratch output location is outside the repo; no scratch artifact was left in the tree.

## Before / after context

Two previously proven root causes were fixed before this verification pass:

1. **Wave-1 report non-determinism.** `wave1/scripts/dedup_check.py` and
   `wave1/scripts/validate_wave1.py` no longer write per-run UTC fields (`checked_at`,
   `validated_at`) into committed reports. The on-disk report JSONs were rebuilt to purge
   those fields. Evidence: `reports/phase9_wave1_determinism.md` shows two consecutive runs
   byte-identical, and the catalog stayed current after a third and fourth validator run.
2. **Stale wave-1 PRESENT sentinel.** `wave1/00_governance/PRESENT.md.json` was re-frozen
   against the current `Vbeta/present_snapshot.json` (plus the newly globbed hydration
   scripts), so `b_present_drift`, `vbeta-tests` and `wave1-tests` no longer report drift.

Historical "before" state, for contrast (not current results):

| Artifact | Earlier state | Now |
|---|---|---|
| `run_gates.py` | `gates=54 pass=32 fail=22 skipped=0` (hydration-era run, `reports/HYDRATION_FINAL_REPORT.md`) | `gates=54 pass=54 fail=0 skipped=0` |
| `validate_wave1.py` | 8/9 with `b_present_drift` FAIL; catalog went stale after every re-run (`reports/phase8_catalog_sentinel_final.md`) | 9/9 PASS; catalog stays current |
| `verify_audit.py` | 1156/1156 checks (`reports/AUDIT_EXECUTIVE_SUMMARY.md`) | 1198/1198 checks |
| `pytest -q` | `13 failed, 892 passed, 1665 subtests passed in 518.17s` (`reports/final_verification_pytest.txt`) | `905 passed, 1665 subtests passed in 1585.88s` |

Preconditions confirmed green before this pass: wave1 9/9, verify_audit 1198/1198,
check_manifests 181/0, 0 machine-path operator leaks, catalog built last.

## Suite results

### 1. `python scripts/run_gates.py`

Exit verdict (exact final line):

```
gates=54 pass=54 fail=0 skipped=0
```

Elapsed (process-handle wait): **00:42:03.6015775** (42 min 03 s).
Failing gates: **none**. Skipped gates: **none**.

All 54 gates reported `[PASS]`, in order: v1-authorship, ml-layer, v3, v31, vbeta-gate,
manifests, line-endings, reproducibility, unit-tests, vbeta-tests, wave1-gate, wave1-tests,
readme-current, solodit-report-current, repro-report-current, stats-current,
rejection-corpus-current, negative-stats-current, f-extension-consistency,
f-extension-current, f-extension-baselines-current, prove-split-current,
prove-ledger-current, rights-consistency, v4-licensing-current, poc-triage-current,
poc-attempts-current, v32-attempts-current, span-audit-current, span-tasks-current,
span-scoring-current, taxonomy-current, root-cause-assignments-current, iaa-sample-current,
iaa-stats-current, api-siblings-current, sibling-review-current,
remediation-report-current, quarantine-report-current, field-coverage-current,
schemas-current, datasheet-current, vbeta-build-current, catalog-current,
benchmark-audit-current, benchmark-holdout-current, benchmark-baselines-current,
benchmark-metrics-current, eval-leakage, eval-leakage-report-current, no-machine-paths,
redaction-current, release-manifest-current, proof-hashes-current.

Notable gate details: `manifests - checked=181 pass=181 fail=0 unknown=0`;
`wave1-gate - [validate_wave1] overall structural verdict: PASS`;
`catalog-current - json catalog is current (918 files)`;
`no-machine-paths - files=2102 leaks=0 pending=0 genuine=2218
read_only_source_layer_unresolved=0`;
`release-manifest-current - 531 released, 1542 not released`.
Standard error was empty.

### 2. `python wave1/scripts/validate_wave1.py`

Exact verdict:

```
[a_single_writer] PASS
[b_present_drift] PASS
[c_dedup] PASS
[d_rights] PASS
[e_benchmark] PASS
[f_label_purity] PASS
[g_j_execution] PASS
[h_group_disjoint_splits] PASS
[i_fully_trainable] PASS
[validate_wave1] overall structural verdict: PASS
```

Wave-1 gates: **9/9 PASS**. Elapsed: **00:00:00.8024849** (0.80 s). Standard error empty.
The re-frozen PRESENT sentinel and the now-deterministic report JSONs are both confirmed.

### 3. `python scripts/verify_audit.py`

Exact summary lines:

```
checks run=1198  passed=1198  failed=0
DISCREPANCIES: none
Full log: reports/audit_verification.txt
```

Elapsed: **00:00:58.9234175** (58.9 s). Standard error empty. Discrepancies: **none**.

### 4. `python -m pytest -q --durations=15`

Exact final line:

```
905 passed, 1665 subtests passed in 1585.88s (0:26:25)
```

Elapsed (process-handle wait): **00:26:28.9841496** (26 min 29 s wall; pytest-internal
1585.88 s). Failing tests: **none**. Skipped: **0**. Xfailed: **0**. No short test summary
of failures was emitted; stdout shows a single all-dot run reaching 100%. Standard error
was empty.

Slowest 15 durations (exact, as reported):

```
283.91s call   tests/test_rights_gate.py::RightsGateLiveTree::test_distribution_view_carries_no_copied_expression
276.85s call   tests/test_rights_gate.py::RightsGateLiveTree::test_gate_is_runnable_and_reports_the_known_findings
238.57s call   tests/test_rights_gate.py::LiveReleaseManifest::test_the_committed_manifest_is_reproducible
154.70s call   tests/test_no_machine_paths.py::MachinePathGateTests::test_the_gate_passes_the_repository
140.88s call   tests/test_no_machine_paths.py::MachinePathGateTests::test_the_repository_has_no_unlisted_machine_path
 41.90s call   tests/test_benchmark_status.py::TestBaselinesAreTrainOnly::test_every_baseline_reports_where_it_was_fitted
 38.10s call   tests/test_json_catalog.py::TestCatalogIsMachineIndependent::test_an_untracked_stray_json_cannot_change_the_catalog
 32.76s call   tests/test_api_siblings.py::ScriptSurface::test_dry_run_writes_nothing
 20.05s call   tests/test_benchmark_status.py::TestStatusComesFromEvidence::test_status_is_deterministic
 19.50s call   tests/test_independent_benchmark.py::TestAdditiveAndReproducible::test_audit_is_deterministic
 15.90s call   tests/test_reproducibility.py::TestLiveGates::test_check_reproducibility_green
 14.69s call   tests/test_eval_leakage.py::TestGateIsRunnable::test_the_gate_passes_on_this_tree
 13.53s call   tests/test_eval_leakage.py::TestProtectedRecordsStayOutOfTheCorpus::test_the_committed_report_is_current
 11.98s call   tests/test_generated_docs.py::TestExploratoryDemotionIsLive::test_scorer_loads_exploratory_only_for_continuity
 11.62s call   tests/test_independent_benchmark.py::TestAdditiveAndReproducible::test_holdout_is_deterministic
```

### 5. Post-suite determinism proof: `python scripts/build_json_catalog.py --check`

Run after all four suites (i.e. after the wave1 rewrites and all other generated-file
checks), with no catalog rebuild in between:

```
json catalog is current (918 files)
```

Elapsed: **00:00:44.8509982** (44.9 s). Standard error empty.

This is the determinism proof in the real gate context: the wave-1 validator rewrote its
reports during suite 2 (and again inside suite 1's `wave1-gate`, with `catalog-current`
later in the same gate run), yet the catalog was still current with no rebuild. The
earlier "validate -> changed report bytes -> stale catalog -> rebuild" cycle is gone.

## Overall outcome

All four target suites met their targets, and the post-suite catalog check passed:

| Suite | Target | Actual | Result |
|---|---|---|---|
| `run_gates.py` | 54/54 | `gates=54 pass=54 fail=0 skipped=0` | MET |
| `validate_wave1.py` | 9/9 | 9/9 gate lines PASS, verdict PASS | MET |
| `verify_audit.py` | 1198/1198 | `checks run=1198 passed=1198 failed=0`, no discrepancies | MET |
| `pytest -q` | 100% PASS | `905 passed, 1665 subtests passed`, 0 failed | MET |
| catalog after all suites | current | `json catalog is current (918 files)` | MET |

**Remaining failures: none.** No partial runs; every suite completed to its own final
summary line.

## Files touched by this verification pass

Only `reports/FINAL_VERIFICATION_RESULTS.md` was written directly. Suite scripts wrote
only their own generated/log/cache artifacts as part of normal execution; no script,
dataset, test, gate, pin or report was edited to force a green result.

Final guard checks after writing this report (both detached, process-handle waited):

```
python scripts/build_json_catalog.py --check  ->  json catalog is current (918 files)
python scripts/check_no_machine_paths.py --quiet  ->  files=2103 leaks=0 pending=0
                                                      genuine=2218 read_only_source_layer_unresolved=0
```

The report itself neither staled the catalog nor introduced a machine-path leak
(the scanned file count rose from 2102 to 2103, exactly this new report).
