# Hydration Final Report

Headline before/after (raw repo-wide audit):

- Rows: 268,776 -> 261,792 (-6,984)
- Files: 189 -> 196 (+7 quarantine/bookkeeping ledgers)
- FULLY_TRAINABLE: 32,744 -> 68,523
- PARTIAL_TEXT_NO_CODE: 87,939 -> 88,655
- METADATA_ONLY_STUB: 148,093 -> 104,614
- Trainable-tables-only FULLY: 32,468 -> 56,123; STUB: 94,873 -> 19,753

Classifier correction: the rights-policy false positive in `explicit_metadata_flag()`
was fixed; `METADATA_ONLY`/`POINTER_ONLY` now only flags extraction-flag fields, so
inline-code+prose rights-governed rows are no longer misbinned as stubs. See
`reports/_classifier_fix_notes.md`.

Verification actually observed (definitive serial re-run, 2026-11-21):
- `build_release_manifest.py --check`: RELEASE_MANIFEST.json reproducible, 0 diffs
  (531 released / 1542 not released).
- `build_json_catalog.py --check`: json catalog current, 0 diffs (918 files).
  (Catalog built LAST, after the manifest refresh following the last check_manifests.py edit.)
- `verify_audit.py`: 1198/1198 PASS, 0 discrepancies.
- `check_manifests.py --quiet`: checked=181 pass=181 fail=0.
- `check_rejection_consistency.py --quiet`: PASS.
- `python wave1/scripts/validate_wave1.py`: 8/9 gates PASS, **overall FAIL** — only
  `b_present_drift` fails. Two tracked files (`Vbeta/present_snapshot.json`,
  `benchmark/manifest.json`) were regenerated after their `canonical_sha256` pins in
  `wave1/00_governance/PRESENT.md.json` were frozen, so their current hashes no longer
  match the pinned values. `wave1-tests` and `vbeta-tests` fail on the same drift. These
  are out-of-scope files; no check or pin was edited to force green.
- `python scripts/run_gates.py`: **completed after >60 min in background** —
  **gates=54 pass=32 fail=22 skipped=0** (exit 1). The 22 failures: v1-authorship, v3,
  reproducibility, unit-tests (2400 s timeout), vbeta-tests, wave1-gate, wave1-tests,
  readme-current, repro-report-current, f-extension-baselines-current, span-audit-current,
  span-tasks-current, taxonomy-current, remediation-report-current, catalog-current,
  benchmark-audit-current, benchmark-holdout-current, benchmark-baselines-current,
  benchmark-metrics-current, eval-leakage, eval-leakage-report-current, no-machine-paths.
  Dominated by stale non-owned generated artefacts and pre-purge v2.2 benchmark/split
  data; no check was weakened. (`catalog-current` failed only because earlier gates in
  the same run rewrote tracked JSON after the catalog was built LAST in step 2.)
- `python -m pytest -q -p no:cacheprovider`: see §5 of `HYDRATION_BEFORE_AFTER.md` for the
  exact reported count; harness repeatedly killed foreground runs at ~43% with multiple
  failures visible.

Full detail, per-layer table, exclusion set and blocker list: `reports/HYDRATION_BEFORE_AFTER.md`.
