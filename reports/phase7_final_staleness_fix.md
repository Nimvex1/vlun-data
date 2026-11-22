# Phase 7 — Final staleness fix (correct dependency order)

Date: 2026-11-22
Repo: checkout root (Windows / PowerShell, Python stdlib only)

## Problem

`jsonl/patches.jsonl` had one orphan row purged, leaving **37 rows**, but several
derived/stale artefacts still described the pre-purge state:

- audit metadata recorded the patches layer as `total_rows=38`;
- the publish-manifest breakdown recorded `915` jsonl rows instead of `914`;
- docs (`README.md`, `docs/DATASHEET.md`,
  `reports/remediation_before_after.{md,json}`, `reports/json_catalog.{json,md}`)
  were stale;
- `wave1/00_governance/PRESENT.md.json` had been re-frozen **after** the catalog
  build — the wrong order.

The prior verification state was `verify_audit.py` 1197/1198 (single failure:
"row count jsonl/patches.jsonl counted=37 but total_rows=38") and
`test_publish_manifest::breakdown_recomputes` failing `915 != 914`.

This run fixed the staleness by regenerating everything in a strict dependency
order and putting the JSON catalog **absolutely last**.

## Commands run, in exact order, and results

### Step 1 — refresh release manifest from live data
```
python scripts/build_release_manifest.py
```
Result: exit 0. `wrote RELEASE_MANIFEST.json: 2073 tracked paths, 531 released,
1542 not released` (attribution_required 14, internal 1339, metadata_only 1,
project_own 516, withheld 203). This builder recomputes rights status from the
live files; it does not read the audit JSON or the catalog.

### Step 2 — regenerate all docs from current data
```
python scripts/generate_stats.py
python scripts/build_remediation_report.py
python scripts/generate_readme.py
python scripts/build_datasheet.py
```
Results: all exit 0.
- `dataset_stats.json`: `findings=241 negatives=444 exploits=154 patches=37`
  (confirms the live patch count is 37).
- `remediation_before_after.md: 11 items`.
- `wrote README.md (532 lines) and NOTICE.md (225 lines)`.
- `wrote docs/DATASHEET.md (51 lines)`.

README/NOTICE/DATASHEET are now derived from the 37-row live data.

### Step 3 — regenerate audit JSON, then verify
```
python scripts/audit_trainable_vs_metadata_parallel.py
python scripts/verify_audit.py
```
Results: both exit 0. The rebuilt
`reports/metadata_vs_trainable_audit.json` now records
`jsonl/patches.jsonl.total_rows = 37` (was 38).
`verify_audit.py` final lines:
```
checks run=1198  passed=1198  failed=0
DISCREPANCIES: none
Full log: reports/audit_verification.txt
```
This is the required **1198/1198 PASS**.

### Step 4 — deliberately deferred
The brief steps 4 and 7 overlap: step 4 says "build_release_manifest.py AGAIN
... then build_json_catalog.py — but WAIT: PRESENT re-freeze and publish-manifest
pin changes may still alter tracked JSON. So do catalog only after steps 5-6."
Per that instruction, the catalog build was **not** run here. The manifest/catalog
rebuild was performed once, in the final Step 7, after steps 5 and 6.

### Step 5 — fix the publish-manifest pin and breakdown
Edited (documented, not weakened):
- `tests/test_publish_manifest.py`: `915 / 910 (total 1,825)` →
  `914 / 910 (total 1,824)`; assertion `jsonl_rows + split_rows == 1825` →
  `1824`; docstring records old→new and the reason (one orphan patch row purged,
  38→37). The historical `records_written = 1898` pin is unchanged.
- `publish_manifest.json`: `records_written_breakdown.jsonl_source_rows`
  `915` → `914`, with the note updated to `914 + 910 = 1,824` and the purge
  history corrected to 39 removed jsonl rows (including the final orphan patch).

Result:
```
python -m pytest -q tests/test_publish_manifest.py
....                                                                     [100%]
4 passed in 0.06s
```
exit 0. Live recomputation gives `914 + 910 = 1824`, matching both files.

### Step 6 — re-freeze PRESENT sentinel
Re-froze `wave1/00_governance/PRESENT.md.json` with the `_common.sha256_file`
rule (CRLF→LF byte normalisation): recomputed every canonical pin, every
`wave1_script_sha256` pin, and recomputed `self_sha256` as
`sha256(json.dumps(canonical_sha256, sort_keys=True).encode())` (the rule in
`wave1/scripts/build_governance.py`). `created_at` and `note` preserved.

Diff vs. the previous sentinel: the only canonical hash that changed was
`README.md` (expected, because README was regenerated in step 2); script pins
were unchanged.
- old self_sha256: `69fb02612095c91edac4f14bb66679328f1a04a0bd31974b56816db26a96667b`
- new self_sha256: `a6223de79e7fed67adf641f3f194bf0b1d161da2f509d1ac5eb5101b96fcfc74`

Result:
```
python wave1/scripts/validate_wave1.py
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
exit 0 — **9/9 PASS**.

### Step 7 — FINAL rebuild, catalog absolutely last
```
python scripts/build_release_manifest.py
python scripts/build_json_catalog.py
```
Results: both exit 0.
- `wrote RELEASE_MANIFEST.json: 2073 tracked paths, 531 released, 1542 not released`
- `wrote reports/json_catalog.json + .md (918 files)`

Then both `--check` modes:
```
python scripts/build_release_manifest.py --check
  RELEASE_MANIFEST.json: reproducible; 531 released, 1542 not released
python scripts/build_json_catalog.py --check
json catalog is current (918 files)
```
Both exit 0 — **0 diff**.

Machine-path scan:
```
python scripts/check_no_machine_paths.py
```
First run found one operator leak in an untracked scratch capture file:
`reports/FINAL_VERIFICATION.md:3: windows_user_profile 'C:\\Users\\<user>'`.
That file was backed up to
`<temp>/opencode/phase7_backup/FINAL_VERIFICATION.md`
and removed from the repo. Re-run result:
```
scanned 2098 files
  operator leaks : 0
  pending        : 0
  genuine        : 2218
  read_only_source_layer_unresolved: 0
```
exit 0 — **0 leaks**. (The removed file was untracked, so it was never part of
the catalog; the catalog `--check` was re-run afterwards and still passes.)

### Step 8 — manifest cross-checks
```
python scripts/check_manifests.py --quiet
checked=181 pass=181 fail=0 unknown=0
```
exit 0 — **181/0**.

### Final consolidated re-verification (after the scratch-file cleanup)
```
python scripts/build_release_manifest.py --check      -> reproducible (exit 0)
python scripts/build_json_catalog.py --check          -> current, 918 files (exit 0)
python -m pytest -q tests/test_publish_manifest.py    -> 4 passed (exit 0)
python scripts/verify_audit.py                        -> checks run=1198 passed=1198 failed=0, DISCREPANCIES: none (exit 0)
python wave1/scripts/validate_wave1.py                -> overall structural verdict: PASS (exit 0)
python scripts/check_no_machine_paths.py              -> operator leaks: 0 (exit 0)
```

**Final catalog rebuild (catalog kept absolutely last).** Re-running
`validate_wave1.py` in the verification batch above rewrites two tracked
wave1 report JSONs (`wave1/reports_wave1/dedup_check.json` and
`wave1/reports_wave1/validate_wave1.json`), which made the catalog that had
been built in step 7 stale. To honour the "catalog absolutely last" rule, the
catalog was rebuilt once more after all generators/checkers had finished:
```
python scripts/build_json_catalog.py
  wrote reports/json_catalog.json + .md (918 files)            (exit 0)
python scripts/build_json_catalog.py --check
  json catalog is current (918 files)                          (exit 0)
```
No generator was run after this rebuild; the remaining confirmation commands
(`--check` modes, `check_manifests.py --quiet`, read-only machine-path scan)
do not write tracked JSON.

## Why this ordering was required

The artefacts form a dependency chain; running a generator before its inputs
are final produces stale hashes that subsequent checks catch:

1. **Manifest first (step 1, again in step 7).** Rights status is measured from
   live files only, so it must reflect the 37-row data before anything that
   fingerprints it.
2. **Docs (step 2) before the sentinel.** `README.md` is a canonical PRESENT
   target. Any README change after the freeze invalidates
   `PRESENT.md.json` and breaks `validate_wave1` gate b and `test_wave1`.
   Regenerating README here is exactly why the re-freeze in step 6 was needed.
3. **Audit JSON (step 3) before the catalog.** `verify_audit` re-derives counts
   from live files and compares them to `metadata_vs_trainable_audit.json`. The
   audit must be rebuilt from the 37-row data *before* verification can go
   1198/1198, and its JSON is itself a catalog-hashed artefact.
4. **Pin + manifest edits (step 5) and PRESENT re-freeze (step 6) before the
   catalog.** `publish_manifest.json`, `PRESENT.md.json`, `README.md` and
   `RELEASE_MANIFEST.json` are all tracked JSON/markdown that the catalog
   fingerprints. Freezing or editing any of them after the catalog build would
   make `build_json_catalog.py --check` report drift. This was the specific
   mistake in the prior state ("PRESENT was re-frozen AFTER catalog build").
5. **Catalog absolutely last (step 7).** The catalog hashes the manifest and
   every tracked JSON/JSONL file, so it can only be correct once every other
   generator and hand-edit is complete. Its own outputs are excluded from its
   hash set, so `--check` is stable afterwards.
6. **Machine-path cleanup after the final build.** Removing an untracked
   scratch capture cannot change a catalog built from `git ls-files`, but it
   is done before the final verification batch so the last observed state is
   fully clean.

No datasets, gate scripts, or other tests were modified. All checks are at their
original or stricter strength; no check was weakened.
