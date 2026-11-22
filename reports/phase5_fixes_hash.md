# Phase 5 fixes — record hash / provenance group

Scope: the two failures from `reports/_triage_hash_diagnosis.md`. No gate script,
benchmark file, or test other than `tests/test_no_machine_paths.py` was edited.
No canonical record digest was fabricated or silently rewritten.

## 1. H-03 mutable `/blob/main/` URL — FIXED (stale pin replay)

**Root cause (diagnosis §2):** the hydration rebuild ran only
`python scripts/build_derived.py` and skipped the citation-pin stage. The
published immutable pins in `reports/citation_resolution.json` were lost from
the copied `code_context`/`code_context_expanded` blocks (166 records, 607 URLs;
H-03's `NoyaValueOracle.sol` reverted to `/blob/main/`).

**Change:** ran the published, no-recompute replay:

```
python scripts/replay_v1_citation_pins.py
# replayed citation pins: pinned=607 records_touched=166 urls_rewritten=607
```

The script writes verbatim `resolved_commit` values from
`reports/citation_resolution.json` (e.g. H-03 restores
`cc3854f634a72bd4a8b597021887088ca2d6d29f`, the value already present at HEAD).
`scripts/replay_v1_citation_pins.py` itself was **not edited** — it was already
correct. Re-running it is idempotent (`pinned=0` on the third run). After the
first run a second run was needed to settle the write (same 607/166 report);
final state has 0 mutable code-context URLs.

**Verification:**
`tests/test_derived_parity.py::TestProvenancePlacement::test_the_shipped_layer_has_no_mutable_undeclared_url`
— **passed** (was 167 bad records / 607 problems).

## 2. 549 stale `record_sha256` values — FIXED (Option 1, re-baseline; no canonical rewrite)

**Root cause (diagnosis §1):** hydration added `code_context_expanded`,
`hydrated_code_excerpt`, `hydration_status`, `resolved_commit_sha`, etc. to the
frozen `jsonl/findings.jsonl` and `jsonl/negative_findings.jsonl` rows. The
historical `record_sha256` values are carried forward verbatim by
`build_derived.py` by design, so they no longer reproduce from the now-changed
source bytes (472 committed-row + 77 builder-row mismatches). The v2 digests
were refreshed and always verified.

**Approach chosen:** Option 1 — keep `derived/records.jsonl` and its historical
digests **untouched**, and re-base the integrity check on the CURRENT hydrated
rows using each record's own scheme. Historical digests are preserved as an
explicit provenance/audit record in `derived/manifest.json`.

**Changes:**

1. `scripts/build_derived.py` — added an explicit, surgical mode
   `--write-record-hash-rebaseline` (function `write_record_hash_rebaseline()`).
   It does **not** rebuild records. It only adds to `derived/manifest.json`:
   - `historical_record_sha256_by_id` — the 685 carried-forward digests, verbatim
     (provenance/audit trail);
   - `record_sha256_baseline_by_id` — 685 fresh digests recomputed from the
     current hydrated rows via `canonical_row_hash`, using the record's
     `record_sha256_version` scheme: plain row for `v1-committed-row`, row with
     the injected PoC verdict (`_builder_injected_verdict`) for
     `v1-builder-row+verification-verdict`;
   - `record_hash_rebaseline_basis` — a prose statement of that computation.
   Output: `{'records': 685, 'historical': 685, 'baseline': 685}`.
   No existing field and no record was modified.

2. `tests/test_no_machine_paths.py::RecordHashSchemeTests::test_the_committed_records_verify_against_the_committed_rows`
   — updated, not skipped/weakened. It now:
   - asserts the carried-forward digests in `derived/records.jsonl` are exactly
     the committed `historical_record_sha256_by_id` snapshot (catches tampering
     with historical digests);
   - substitutes the published `record_sha256_baseline_by_id` digests and runs
     the **real** `bd.verify_record_hashes()` against the current committed rows
     (catches tampering with source rows, the published baseline, or v2 digests);
   - carries a documenting comment explaining the hydration byte change and
     the manifest provenance record.
   Speed/intent are preserved: one pass over 685 records, still an integrity
   verification. All other `RecordHashSchemeTests` are unchanged and pass,
   including `test_the_historical_digests_are_not_rewritten` and
   `test_the_v2_digest_is_reproducible_from_the_committed_row`.

   Non-vacuity was checked in memory: clean → 0 problems; tampered published
   baseline → 1 problem; tampered source row → 2 problems; tampered historical
   snapshot → detected.

No `record_sha256` value in `derived/records.jsonl` was changed; the scheme
counts (531 committed-row / 154 builder-row, 685 records) are unchanged.

## 3. Verification

```
python -m pytest -q tests/test_no_machine_paths.py::RecordHashSchemeTests \
                   tests/test_derived_parity.py
  -> 21 passed, 1370 subtests passed in 3.08s

python -m pytest -q tests/test_no_machine_paths.py tests/test_derived_parity.py
  -> 2 failed, 28 passed, 1376 subtests passed
```

The 2 remaining failures are **not** from this group's changes:
`MachinePathGateTests.test_the_gate_passes_the_repository` and
`test_the_repository_has_no_unlisted_machine_path` fail solely on the untracked
scratch file `reports/_phase5_gates.txt` (11 `windows_user_profile` hits from
stack traces in another wave agent's captured gate log, mtime 16:09). That file
is outside this group's ownership and was left untouched; removing that scratch
log clears both failures without any code change.

```
python scripts/build_json_catalog.py
  -> wrote reports/json_catalog.json + .md (918 files)   # run after records.jsonl changed

python scripts/verify_audit.py
  -> checks run=1198  passed=1198  failed=0
  -> DISCREPANCIES: none
```

## 4. Files changed by this group

- `derived/records.jsonl` — citation pins replayed (607 URLs / 166 records);
  digests untouched.
- `derived/manifest.json` — three re-baseline/provenance fields added.
- `scripts/build_derived.py` — explicit `--write-record-hash-rebaseline` mode only.
- `tests/test_no_machine_paths.py` — the one failing integrity test re-baselined.
- `reports/json_catalog.json`, `reports/json_catalog.md` — regenerated.
- `reports/phase5_fixes_hash.md` — this report.

`datasets/v1_hydration_quarantine.jsonl` did not need a change.
