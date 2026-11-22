# Phase 9 — Wave-1 report determinism and catalog-staleness cycle proof

Scope: remove the volatile wall-clock fields from the two committed Wave-1
gate reports, re-freeze the `PRESENT.md.json` sentinel, and prove that the
wave1 validation cycle no longer stales the JSON catalog.

Root cause: `wave1/scripts/dedup_check.py` wrote a `checked_at` field and
`wave1/scripts/validate_wave1.py` wrote a `validated_at` field (both from
`utc_now()`) into reports that are themselves committed and byte-hashed by
`reports/json_catalog.json`. Every fresh run changed those bytes, so the
catalog went stale immediately after each validation. Both writes were
removed (and `utc_now` dropped from both imports); the on-disk reports were
then rebuilt to purge the stale fields. No check was weakened and no other
script, dataset, test or gate was edited.

## 1. Report determinism — two consecutive runs (stale-PRESENT state)

Hash method: `sha256` of the file bytes after `CRLF -> LF` normalization
(identical to the catalog's own `describe()` normalization; the files are
written with `newline="\n"`, so raw and normalized hashes coincide).

| Run | `wave1/reports_wave1/dedup_check.json` | `wave1/reports_wave1/validate_wave1.json` |
|---|---|---|
| 1 | `88d6a9d7b111eaf7a01052c3dcdbc8979f0a3fafd3208ef3f72e4138681d76e8` | `9d14a68840459007b6d8256a00bdebb24a14b7efe945a90606b8fcc1b0ad75cf` |
| 2 | `88d6a9d7b111eaf7a01052c3dcdbc8979f0a3fafd3208ef3f72e4138681d76e8` | `9d14a68840459007b6d8256a00bdebb24a14b7efe945a90606b8fcc1b0ad75cf` |

**Byte-identical across runs 1 and 2: YES.** (Gate `b_present_drift` was
still FAIL in both runs because the PRESENT sentinel pins were stale; that
state is fixed in section 2. In run 1 all other 8 gates, including
`e_benchmark`, were PASS.)

## 2. `wave1/00_governance/PRESENT.md.json` re-freeze

Recomputed every pin with `sha256_file` (CRLF→LF normalization) over all
`PRESENT_TARGETS` plus all wave1 scripts, then recomputed `self_sha256` as
`sha256(json.dumps(canonical_sha256, sort_keys=True).encode())` — exactly the
generator's rule. The scalar fields (`created_at`, `note`, `missing`) were
preserved so the file remains deterministic; `missing` is `[]`. Only this
file was written (the governance builder was deliberately not run, because
it also refreshes `created_at` and rewrites files outside this subagent's
ownership).

Changed pins (all other canonical pins were already current):

| Section | Path | Old | New |
|---|---|---|---|
| canonical | `Vbeta/present_snapshot.json` | `0083886a1b93db30d41cbab162a96ba57411f7c80348c79370d649aa0e73f7a1` | `8fb5366b5996ec0944f7afb52547a475b88476c70f86844ec36477f95cb3a7cf` |
| script | `scripts/dedup_check.py` | `6dca8713f6aee57d72604f4af6a068bd1d909283340be0c2957c71f891efa5de` | `b9627ea8bed821d25535c59f737aca8e6cbaf256021a50d541b9648697f764eb` |
| script | `scripts/validate_wave1.py` | `3a6b62a0744e160e1b9d43cd45a0ebd9d663602dd894eaaa57d99f54f7a9d51f` | `78c7ec1b629f8eaa5c5654041cb07b8857d28d497549863d5137f69b92576374` |
| script | `scripts/hydration_lib.py` | *(absent)* | `aef8c1d4742963a30e3bf1ce5ab02d917d976e093e43f292fbf3716fd6120c4d` |
| script | `scripts/propagate_hydration.py` | *(absent)* | `c90eae9d39976553ac2ea91609dc207dccae011095f74452a292b5414e0bf134` |
| — | `self_sha256` | `a6223de79e7fed67adf641f3f194bf0b1d161da2f509d1ac5eb5101b96fcfc74` | `7a70aa8ed94c814a004e8d53c2f7fa7b85a9bbf03a5a80162b18f54ddb5293e5` |

The two newly pinned scripts are picked up by the generator's `*.py` glob
(they were previously unglobed); this matches `build_governance.py` exactly.
The script-pin changes are the expected consequence of removing the volatile
timestamp writes.

## 3. Post-refreeze gate run

After the re-freeze, `python wave1/scripts/validate_wave1.py` reports:

```
[a_single_writer] PASS   [b_present_drift] PASS   [c_dedup] PASS
[d_rights] PASS          [e_benchmark] PASS      [f_label_purity] PASS
[g_j_execution] PASS     [h_group_disjoint_splits] PASS
[i_fully_trainable] PASS
[validate_wave1] overall structural verdict: PASS
```

**Wave-1 gates: 9/9 PASS.** `python -m pytest -q wave1/tests/test_wave1.py`
→ **15 passed in 0.81s**.

The `validate_wave1.json` bytes legitimately changed from the section-1 run
because `b_present_drift` went FAIL → PASS:

| Report | Hash after re-freeze (runs 3, 4, 5) |
|---|---|
| `dedup_check.json` | `88d6a9d7b111eaf7a01052c3dcdbc8979f0a3fafd3208ef3f72e4138681d76e8` (unchanged) |
| `validate_wave1.json` | `e0b143812b382f038090d3ad0d69d6f7dd3a29df592eadab0a08730c4e54f502` |

## 4. Generator rebuild (catalog strictly last)

1. `python scripts/build_release_manifest.py` → `RELEASE_MANIFEST.json`:
   2073 tracked paths, 531 released, 1542 not released.
2. `python scripts/build_json_catalog.py` → `reports/json_catalog.json` +
   `.md`: **918 files** (last generator run).

## 5. Catalog-survives-third-run proof

Ran `python wave1/scripts/validate_wave1.py` a **third** time (after the
catalog was built), then `python scripts/build_json_catalog.py --check`:

```
[validate_wave1] overall structural verdict: PASS
dedup_check.json 88d6a9d7b111eaf7a01052c3dcdbc8979f0a3fafd3208ef3f72e4138681d76e8
validate_wave1.json e0b143812b382f038090d3ad0d69d6f7dd3a29df592eadab0a08730c4e54f502
json catalog is current (918 files)
```

**Catalog current after the third validation run: YES.** No re-run of the
catalog builder was needed. As an extra confirmation a **fourth** validation
run produced the same two hashes and `json catalog is current (918 files)`
again. The stale-at-every-run cycle is broken: the cycle is
validate → (identical report bytes) → catalog stays current.

## 6. Repository-wide checks

| Command | Result | Exit |
|---|---|---|
| `python scripts/check_manifests.py --quiet` | `checked=181 pass=181 fail=0 unknown=0` | 0 |
| `python scripts/verify_audit.py` | `checks run=1198 passed=1198 failed=0`, `DISCREPANCIES: none` | 0 |
| `python scripts/check_no_machine_paths.py` | scanned 2101 files; **operator leaks: 0**, pending: 0 | 0 |

No machine-path leaks, so no scratch cleanup was required. Final state after
all checks (including this report, a `.md` file the catalog does not scan):
a final `build_json_catalog.py --check` still reports the catalog current.
