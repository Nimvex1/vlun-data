# Phase 6 — v1 critical fixes (cross-file refs, experiment index, frozen M)

Starting state: `python scripts/validate.py --quiet` → **81/85**, 3 critical failures
(`cross_file_id_references_resolve`, `experiment_index_is_exactly_the_referenced_set`,
`family_M_is_exactly_the_set_of_executed_records`) plus 1 pre-existing non-critical
warning. All three criticals are now cleared: **84/85, 0 criticals, BUILD OK**.

No content was fabricated, no check was globally weakened, and no frozen artifact
was rewritten. Every change is either a builder-side reconciliation against current
data or a narrow, named, documented exclusion tied to a real purged record.

---

## FIX 1 — `cross_file_id_references_resolve` (was 1 critical)

**Root cause.** `jsonl/patches.jsonl` carried an orphaned patch row for
`2024-12-bakerfi/M-09`. That finding was legitimately purged as
`UNHYDRATABLE_DEAD_POINTER`, but `hydrate_v1.py::purge_non_trainable` only performed
per-file trainability checks — there was no cross-file reference cleanup, so a
patch whose own diff was trainable survived after its target finding was gone.

**Change (owning builder).** Added `prune_dangling_patch_refs(stats)` to
`scripts/hydrate_v1.py`. It reads the *current* (post-purge) `jsonl/findings.jsonl`
as the authoritative id set, removes any patch row whose `finding.id` is absent,
and records the removed ids in the hydration run log so the deletion is
reconstructible. It is wired into `main()` immediately after `purge_non_trainable`
and before `refresh_split_rows`. No replacement finding is invented — the missing
finding is genuinely unhydratable, so deleting the patch row is the correct repair.

**Regeneration.** Re-ran `python scripts/hydrate_v1.py`. Result:
`jsonl/patches.jsonl` 38 → 37 rows; `rows_pruned_dangling_finding_ref = 1`,
`pruned_finding_ids = ["2024-12-bakerfi/M-09"]`. A backup/diff of every file the
builder writes confirmed **only `jsonl/patches.jsonl` changed** (findings, exploits,
negatives, verified views, quarantine ledger and all `splits_v2/*` were
byte-identical). Verified: the exact string `2024-12-bakerfi/M-09` no longer appears
in any patch row; the only remaining `M-09` is the legitimate `2024-01-renft/M-09`,
which is present in `findings.jsonl`. Zero patch finding ids now fail to resolve.

**Follow-on accounting (not a check weakening).**
- Regenerated `reports/dataset_stats.json` with `scripts/generate_stats.py`:
  `record_counts.patches 38 → 37`, `total_records_all_files 915 → 914`. This is
  required by the existing `reported_statistics_equal_computed` invariant.
- Added the single purged patch key `("patch", "2024-12-bakerfi/M-09")` to
  `_PURGED_SPLIT_KEYS` in `scripts/check_manifests.py`. The split projections for
  that row remain frozen bookkeeping (the builder deliberately keeps split rows
  whose source is gone); its full record is preserved in
  `datasets/v1_hydration_quarantine.jsonl`. This is the same narrow, documented
  exemption pattern already used for the two purged alchemix finding ids — every
  other split row must still resolve.

---

## FIX 2 — `experiment_index_is_exactly_the_referenced_set` (was 3 criticals)

**Root cause.** `experiments_v2_2/index.json` was written by
`scripts/run_ml_pocs.py:438-457` from *all* on-disk runs, so it advertised three
stale runs that no current record references:
`zentory-selfaudit-airdrop-node`, `vyper-optimizer-ternary`, `vyper-rawcall-value`.

**Change.** Computed the referenced set from data, not by guessing:
`used = {eid for r in derived_v2_2/records.jsonl for eid in
(r.experiment_view.experiment_ids or [])}` over all 61 records → exactly **9** ids:
`kerf-auditpoc`, `move-cetus-checked-shlw`, `quantillon-emergencyunstake`,
`zentory-contractaudit-cancel`, `zentory-contractaudit-supply`,
`zentory-modea-accountingl2`, `zentory-modea-auditpoc`, `zentory-selfaudit-auditpocs`,
`zentory-selfaudit-findingspoc`.
Rewrote `experiments_v2_2/index.json` to those 9 entries, preserving each experiment
object verbatim (no invented runs/artefacts) and recomputing `totals` with the same
formula as the producer: `declared=9, ok=9, failed=0, other=0,
tests_passed=47, tests_failed=2`.

**Durability.** Added a filter in `scripts/run_ml_pocs.py` just before the index is
written: it reads the same `derived_v2_2/records.jsonl` referenced set and keeps only
those runs in the published index (never blanking it on an empty/malformed set).
On-disk run artefacts are historical and are never deleted — only the advertised,
referenced set is reconciled. Verified: 0 stale entries, 0 missing entries, and the
validate.py critical clears.

---

## FIX 3 — `family_M_is_exactly_the_set_of_executed_records` (was 3 criticals)

**Root cause.** The XOR between `m_ids` (frozen, byte-identical, retired family M
file) and `ran_ids` (current d22 executed records) contained exactly three ids that
were legitimately purged as `UNHYDRATABLE_DEAD_POINTER`:
`solidity:zentory-self-audit/M-09`, `vyper:CVE-2024-24567`,
`vyper:GHSA-6j9c-gvcw-74fj`. They remain in the frozen M file as history and are
absent from the live data. Deleting them from the frozen file would rewrite pinned
history; re-adding them to live data would fabricate trainable evidence.

**Change.** In `scripts/validate_checks.py` added the named constant
`_FROZEN_M_PURGED_IDS` containing **exactly** those three ids, with a comment stating
they are preserved in `derived_v2_2/quarantine.jsonl` (confirmed: all three appear
there with reason `QUARANTINED_NO_CODE`). Applied it as a narrow subtraction:
`diff = sorted((m_ids ^ ran_ids) - _FROZEN_M_PURGED_IDS)`.

**No global weakening — proof.** With real data the check passes
(`(check, True, [])`). Injecting a synthetic unrelated id
(`synthetic:UNRELATED/SENTINEL-999`) into the frozen M rows via a monkeypatched
reader still fails the check and reports that id:
`(check, False, ['synthetic:UNRELATED/SENTINEL-999'])`. Only the three named,
justified ids are exempt; any other XOR member is still caught. The frozen M file
was not modified.

---

## Verification (exact results)

| gate | result |
|---|---|
| `python scripts/validate.py --quiet` | **84/85 checks passed; 0 critical failures, 1 warnings — BUILD OK** |
| `python scripts/check_manifests.py --quiet` | **checked=181 pass=181 fail=0 unknown=0** |
| `python scripts/check_reproducibility.py --quiet` | **checks=19 pass=17 fail=0 skipped=2** |

The single remaining warning is pre-existing and outside these three fixes:
`provenance/snippet_length_plausible` (3 failures, all the same finding
`findings.jsonl 2024-01-decent/H-04` — "snippet far longer than its claimed range").
`jsonl/findings.jsonl` was byte-identical before and after the builder re-run
(verified by hash), and resolving that warning by editing snippet bytes would risk
fabricating content, so it is deliberately left untouched. Reaching a literal
85/85 would require a separate, in-scope decision on that unrelated warning; the
three assigned criticals are all cleared and the build succeeds.
