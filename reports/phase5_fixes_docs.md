# Phase 5 fixes — generated docs / report pin

Scope: clear the final two pytest failures in `tests/test_generated_docs.py`
(`TestReproducibilityReportIsGenerated::test_report_is_generator_output` and
`::test_report_renders_on_a_fresh_clone`). Both failed because
`build_repro_report.py --check` reported `STALE reports/reproducibility_report.md`.
No check was weakened, no test skipped, and no dataset was touched.

## Root cause

`reports/reproducibility_report.md` had been **hand-edited**: its
`reproducibility` row read `19 checks | 2` critical failures. The generator
(`scripts/build_repro_report.py`) composes that cell from the *committed*
`reports/reproducibility_checks_summary.json`, whose `checks_failed_critical`
is `0`. A hand-edited generated file is exactly the drift the doc gate exists
to catch, so `--check` correctly failed and both tests failed with it.

The hand-edit reflected a *previous* state of the reproducibility gate. That
gate (`scripts/check_reproducibility.py`) was subsequently fixed: it now runs
19 checks with 17 passing, 0 failing and 2 pre-existing honest
`skipped_no_network` skips. Its committed summary was updated to
`checks_total: 19`, `checks_failed_critical: 0`. The correct value in the
report is therefore **0**, not the stale hand-written 2.

## Fix — regenerate, do not hand-edit

Ran the documented generator so the report is once again its byte-for-byte
output (no manual edit of the `.md`):

```
python scripts/build_repro_report.py
  -> wrote reports/reproducibility_report.md (56 lines)
```

The `reproducibility` row now reads `19 checks | 0`. A `git diff` of the report
against HEAD is empty: the regeneration restored the file to the committed,
generator-produced content and removed the uncommitted hand-edit.

No change was needed to `scripts/build_repro_report.py` itself — the generator
was correct; only its output had been overwritten by hand.

## Documenting comment / pin context (other agents' edits this phase)

- `publish_manifest.json` — the `records_written_breakdown` was re-frozen to
  live data: `jsonl_source_rows` 953 → **915**, `splits_v2_rows` 945 → **910**
  (total 1,825 after the hydration/purge). Its `note` now documents the
  recomputation. The `records_written` key (1898) is deliberately **left
  frozen**: it is the v1 historical publish figure pinned as
  `v1_manifest_records_written` by `scripts/audit_pre_upgrade.py` and copied
  into `reports/pre_upgrade_audit.json`, `reports/rights_history_exposure.json`
  and `reports/rights_inventory.json`. `tests/test_publish_manifest.py`
  guards both facts explicitly (live breakdown = 1,825; frozen pin = 1,898).
- `tests/test_generated_docs.py` — **no edits made**. All 28 tests pass
  unchanged once the report was regenerated; no stale test expectation
  remained, so no documenting comment was required there.

## Verification

```
python scripts/build_repro_report.py --check
  -> reproducibility_report.md is current                       (exit 0)

python -m pytest -q tests/test_generated_docs.py
  -> 28 passed                                                  (exit 0)

python -m pytest -q tests/test_benchmark_status.py \
      tests/test_generated_docs.py \
      tests/test_independent_benchmark.py \
      tests/test_publish_manifest.py \
      tests/test_json_catalog.py
  -> 90 passed in 131.21s (0:02:11)                             (exit 0)
```

Exact counts: **28 passed** in `test_generated_docs.py`; **90 passed** across
the full five-file set (0 failed, 0 skipped, 0 errors). The full five-file set
was re-run after the catalog rebuild (below) and passed again:
**90 passed in 231.29s (0:03:51)** — identical result, no failures.

## Catalog resync (run last)

`publish_manifest.json` is a tracked JSON changed earlier in this phase, so
the dependent generated files were rebuilt last in dependency order:

```
python scripts/build_release_manifest.py
  -> wrote RELEASE_MANIFEST.json: 2073 tracked paths,
     531 released, 1542 not released
python scripts/build_json_catalog.py
  -> wrote reports/json_catalog.json + .md (918 files)
python scripts/build_json_catalog.py --check
  -> json catalog is current (918 files)                       (exit 0)
```

The rebuilds were byte-identical to the files already in the working tree
(`git diff --stat` for `RELEASE_MANIFEST.json` and
`reports/json_catalog.{json,md}` was unchanged), so no test expectation was
invalidated. The full five-file pytest set was re-run afterwards and stayed
green (90 passed). Note: a `build_release_manifest.py --check` was attempted
first but was pathologically slow in this environment (~4 min, no output); it
was superseded by the actual rebuild above, which completed normally.

## Files changed by this fix

- `reports/reproducibility_report.md` — regenerated from its generator
  (reproducibility critical failures 2 → 0).
- `reports/phase5_fixes_docs.md` — this report.

No test, check script, schema, or dataset was modified by this fix.
