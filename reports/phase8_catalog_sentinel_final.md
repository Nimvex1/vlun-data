# Phase 8 — Final catalog / sentinel ordering fix (BLOCKED: two real defects)

Date: 2026-11-22
Repo: checkout root (Windows / PowerShell, Python stdlib only)

## Outcome

The prescribed order was executed. The catalog was rebuilt as the last generator
and is currently `--check` current, but the requested final state is **not**
achievable without touching files the brief forbids. Two independent, proven
defects block a durable fix:

1. **Vbeta re-freeze vs wave1 PRESENT pin conflict.** Sanctioned re-freezing of
   `Vbeta/present_snapshot.json` necessarily changes that file's own hash. Wave1's
   `PRESENT.md.json` (explicitly out of scope) pins the OLD hash, so `validate_wave1`
   gate b and `wave1/tests/test_wave1.py::TestPresent::test_canonical_hashes_match`
   now fail.
2. **wave1 report rewrites are non-deterministic.** Both report JSONs carry
   per-run UTC timestamps (`checked_at`, `validated_at`), so they are byte-different
   on every validator run. A catalog built after wave1 therefore goes stale again
   the moment the validator is re-run. This is the real root cause of the recurring
   "catalog-current" failure.

No check was weakened, no dataset/gate script/test was edited, and no hash was
fabricated. The two remaining failures are reported with evidence below.

## Commands run, in exact order, with results

### Step 1 — re-freeze Vbeta sentinel
```
python Vbeta/scripts/validate_vbeta.py --resnapshot "README regenerated in final staleness fix"
python -m pytest -q Vbeta/tests/test_vbeta.py
```
- resnapshot: exit 0 (`resnapshotted: README regenerated in final staleness fix`).
- Vbeta tests: **39 passed** (exit 0). The `test_present_sentinels_unchanged` drift is fixed.
- Diff of `Vbeta/present_snapshot.json`: `README.md` cc7ad496… -> 74983570… (correct),
  plus `benchmark/manifest.json` c021586f… -> 612c9985…, `derived_v3/manifest.json`
  51c38529… -> 0b543184…, and JSON indentation normalised to the builder's
  `sort_keys=True, indent=2` form. These are all live values recomputed by the
  sanctioned builder, not hand edits.

### Step 2 — run wave1 validator (FAILED, see blocker 1)
```
python wave1/scripts/validate_wave1.py
```
```
[a_single_writer] PASS
[b_present_drift] FAIL
[c_dedup] PASS
[d_rights] PASS
[e_benchmark] PASS
[f_label_purity] PASS
[g_j_execution] PASS
[h_group_disjoint_splits] PASS
[i_fully_trainable] PASS
[validate_wave1] overall structural verdict: FAIL
```
Expected 9/9; got 8 structural PASS + 1 FAIL. Two independent runs gave the same
verdict. Gate b detail:
```
canonical_drift: [{"path": "Vbeta/present_snapshot.json",
  "expected": "0083886a1b93db30d41cbab162a96ba57411f7c80348c79370d649aa0e73f7a1",
  "actual":   "8fb5366b5996ec0944f7afb52547a475b88476c70f86844ec36477f95cb3a7cf"}]
```

### Step 3 — determinism check (FAILED, see blocker 2)
Hashed the two report JSONs, re-ran `validate_wave1.py`, hashed again:
```
wave1/reports_wave1/dedup_check.json     before=84E67366…  after=7FCD58C1…  stable=False
wave1/reports_wave1/validate_wave1.json  before=A70A8148…  after=3F290702…  stable=False
```
Byte diff proves the cause is timestamps only:
```
dedup_check.json:      "checked_at":    "2026-11-22T14:31:18Z" -> "2026-11-22T14:31:25Z"
validate_wave1.json:   "validated_at":  "2026-11-22T14:31:19Z" -> "2026-11-22T14:31:25Z"
```
No other field changed. `wave1/scripts/_common.py::utc_now()` supplies these values,
so determinism cannot be restored without editing a gate script (forbidden).

### Step 4 — release manifest
```
python scripts/build_release_manifest.py
```
exit 0; `wrote RELEASE_MANIFEST.json: 2073 tracked paths, 531 released, 1542 not released`.

### Step 5 — JSON catalog (first build)
```
python scripts/build_json_catalog.py
```
exit 0; `wrote reports/json_catalog.json + .md (918 files)`.

### Step 6 — verification checks
```
python scripts/build_json_catalog.py --check     -> json catalog is current (918 files); exit 0
python scripts/build_release_manifest.py --check -> RELEASE_MANIFEST.json: reproducible; exit 0
python scripts/check_manifests.py --quiet        -> checked=181 pass=181 fail=0 unknown=0; exit 0
python scripts/verify_audit.py                   -> checks run=1198 passed=1198 failed=0,
                                                    DISCREPANCIES: none; exit 0
python scripts/check_no_machine_paths.py         -> scanned 2100 files, operator leaks 0; exit 0
```
Machine-path cleanup: untracked scratch file `reports/FINAL_VERIFICATION_RESULTS.md`
had one `windows_user_profile` leak. It was backed up to a temp backup directory
outside the repo (`<temp>/opencode/phase8_backup/FINAL_VERIFICATION_RESULTS.md`)
and removed from the repo (verified untracked via `git ls-files`, so it was never
catalog-hashed).

### Step 7 — the two previously failing checks
```
python -m pytest -q tests/test_json_catalog.py Vbeta/tests/test_vbeta.py
```
**45 passed** (exit 0). Catalog test and Vbeta sentinel test both green.

### Extra proof of blocker 2 (catalog fragility)
```
python scripts/build_json_catalog.py --check   -> current (exit 0)
python wave1/scripts/validate_wave1.py         -> rewrites timestamps only
python scripts/build_json_catalog.py --check   -> STALE, exit 1:
   "entry differs: wave1/reports_wave1/dedup_check.json,
    entry differs: wave1/reports_wave1/validate_wave1.json"
```
Then, to leave a consistent tree:
```
python scripts/build_json_catalog.py           -> wrote catalog (918 files)
python scripts/build_json_catalog.py --check   -> current (exit 0)
```
This was the FINAL generator run; no generator followed it.

## Blocker 1 — detail and required fix (out of scope)

`wave1/00_governance/PRESENT.md.json` pins
`"Vbeta/present_snapshot.json": "0083886a1b93db30d41cbab162a96ba57411f7c80348c79370d649aa0e73f7a1"`.
That pin describes the pre-resnapshot file (which carried the stale README hash
`cc7ad496…`). The sanctioned Vbeta re-freeze changes the file to
`8fb5366b…`. A file cannot both contain the corrected README hash and retain the
hash of its stale self, so `validate_wave1` gate b and
`wave1/tests/test_wave1.py::TestPresent::test_canonical_hashes_match` cannot pass
while the pin is frozen. Confirmed test failure:
```
AssertionError: '8fb5366b…' != '0083886a…' : drift in Vbeta/present_snapshot.json
```
The only sanctioned way to restore green is to re-freeze the wave1 PRESENT sentinel
via `python wave1/scripts/build_governance.py` (the writer of that file), then rebuild
the catalog. That file was explicitly declared out of scope for this run, so it was
NOT done.

## Blocker 2 — detail and required fix (out of scope)

`wave1/scripts/dedup_check.py` and `wave1/scripts/_common.py::utc_now()` write a
fresh UTC timestamp into `wave1/reports_wave1/dedup_check.json` (`checked_at`) and
`wave1/reports_wave1/validate_wave1.json` (`validated_at`) on every validator run.
The catalog fingerprints those files, so ordering the catalog "last" only makes it
current until the next validator invocation. A durable fix requires one of:
- emit a fixed/derived timestamp (or no timestamp) in those two reports, or
- exclude the two volatile timestamp fields from the catalog hash set.
Both require editing gate scripts or the catalog builder, which is forbidden here.

## Summary of gate state

- Vbeta sentinel drift: FIXED (39/39 + catalog test green).
- Catalog is currently current and the manifest is reproducible.
- verify_audit 1198/1198, check_manifests 181/0, machine-path leaks 0.
- wave1 validator: 8/9 structural gates pass; `b_present_drift` FAIL (blocker 1).
- Catalog determinism across a validator re-run: FAIL (blocker 2).

## Post-report state reconciliation

An informational `python scripts/run_gates.py --quiet` was attempted for a final
tally. It hung in `unittest discover -s tests` (18+ minutes) and was terminated;
it had rewritten `Vbeta/reports_vbeta/validation_vbeta.json`, making the catalog
temporarily stale. Therefore the catalog was rebuilt once more as the last
generator after all generators/checkers had stopped:

```
python scripts/build_json_catalog.py           -> wrote catalog (918 files)
python scripts/build_json_catalog.py --check   -> current (exit 0)
python -m pytest -q tests/test_json_catalog.py Vbeta/tests/test_vbeta.py
                                               -> 45 passed (exit 0)
```
No generator was run after that rebuild. The report file itself was normalised
to avoid a machine-path leak (`check_no_machine_paths.py` -> operator leaks 0).

No fabrication, no weakening. This report records the blockers rather than
papering over them.
