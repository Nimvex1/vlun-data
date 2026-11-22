# Phase 6 — Stale-artefact regeneration

Final regeneration of the four artefacts that failed as STALE after the last data
regeneration. All commands run from the repository root with Python stdlib only.

## Ownership / scope

Regenerated (this task):

- `scripts/generate_readme.py` output — `README.md`, `NOTICE.md`
- `scripts/generate_stats.py` output — `reports/dataset_stats.json`
- `scripts/build_remediation_report.py` output — `reports/remediation_before_after.{md,json}`
- `Vbeta/present_snapshot.json` — the Vbeta test's OWN sentinel (via the sanctioned
  `--resnapshot` path), NOT wave1 `PRESENT.md.json`
- this report

Explicitly NOT touched: wave1 `PRESENT.md.json`, gate scripts, datasets, tests,
release manifest, or catalog (the release manifest/catalog rebuild is owned by a
separate agent and must run LAST).

## Step 1 — Regenerate (in order)

| # | Command | Exit code | Output |
|---|---------|-----------|--------|
| 1 | `python scripts/generate_readme.py` | 0 | `wrote README.md (532 lines) and NOTICE.md (225 lines)` |
| 2 | `python scripts/generate_stats.py` | 0 | `wrote reports\dataset_stats.json  findings=241 negatives=444 exploits=154 patches=38` |
| 3 | `python scripts/build_remediation_report.py` | 0 | `remediation_before_after.md: 11 items` |

Note on a mid-run data shift: the first pass of this sequence produced README text
based on `reports/validation_report.json` = 77/85 passed, 7 critical failures.
A concurrent agent then updated that gate report (mtime 2026-11-22T17:03:36+05:30)
to 78/85 passed, 6 critical failures. The first-pass `README.md` and remediation
`--check` consequently reported STALE. The three generators were re-run against
the settled data (same commands, all exit 0), after which every check passed and
the inputs were verified stable (gate-report mtime unchanged on re-check).

## Step 2 — Direct `--check` gates

Final results (after the data settled):

| Command | Exit code | Output |
|---------|-----------|--------|
| `python scripts/generate_readme.py --check` | 0 | `README.md and NOTICE.md are current` |
| `python scripts/generate_stats.py --check` | 0 | `reports/dataset_stats.json is current` |
| `python scripts/build_remediation_report.py --check` | 0 | `remediation report is current` |

## Step 3 — Vbeta own sentinel + test

The Vbeta test `test_present_sentinels_unchanged` enforces that the hashes in
`Vbeta/present_snapshot.json` match the current PRESENT files. Regenerating
`README.md` changed its hash (old sentinel `d8c0bb24...`, new `cc7ad496...`), so
the sentinel was re-frozen using the sanctioned writer:

| Command | Exit code | Output |
|---------|-----------|--------|
| `python Vbeta/scripts/validate_vbeta.py --resnapshot "Phase6 final: re-freeze Vbeta PRESENT sentinels after README.md regeneration by scripts/generate_readme.py (stale-artifact remediation)"` | 0 | `resnapshotted: Phase6 final: ...` |
| `python -m pytest -q Vbeta/tests/test_vbeta.py` | 0 | `....................................... [100%]` / `39 passed in 0.70s` |

New `README.md` sentinel: `cc7ad496110de2363dab4f172c446586184e741aee8ac41f214f1e10ca7e53bc`
Reason recorded in `present_snapshot.json`: "Phase6 final: re-freeze Vbeta PRESENT
sentinels after README.md regeneration by scripts/generate_readme.py (stale-artifact
remediation)".

## Step 4 — Deferred

Release manifest and catalog were NOT rebuilt here (owned by a separate agent, to
run LAST after all data changes).

## Summary

- Artefacts regenerated: `README.md`, `NOTICE.md`, `reports/dataset_stats.json`,
  `reports/remediation_before_after.md`, `reports/remediation_before_after.json`.
- All three generator `--check` gates: PASS (exit 0).
- Vbeta present sentinel re-frozen; `Vbeta/tests/test_vbeta.py`: 39 passed (exit 0).
- No checks weakened; no gate scripts, datasets, tests, wave1 PRESENT, release
  manifest, or catalog modified.
