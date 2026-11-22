# Phase 5 fixes — span-scoring / v2.2 stale test pins

**Scope:** `tests/test_span_scoring.py` (fixtures only — test logic unchanged),
`tests/test_v22_adjudicated_consumers.py`, and this report.
No dataset `.jsonl`, builder, benchmark, or other test file was modified.

## Verdict

All 9 failures were **stale test/fixture pins (triage class b)**, not stale
artifacts and not genuine data bugs. Every owning builder reports its committed
artifact current:

```
build_derived_v22.py --check        -> problems: 0
build_benchmark_v22.py --check      -> everything built, nothing written
build_canonical_training.py --check -> 12112 examples, 5 chunks
build_span_tasks.py --check         -> OK (4623 keys)
score_span_tasks.py --check         -> OK
build_splits_v22.py --check         -> train 443 / validation 273 / test 253
```

The pinned-away records/rows were deliberately removed from every **trainable**
layer by the audited hydration/purge and are preserved in quarantine:
`derived_v2_2/quarantine.jsonl`, `derived_v3/quarantine.jsonl`,
`splits_v3/quarantine.jsonl`, the adjudication JSON, the immutable `jsonl_ml/`
source layer, and the frozen `benchmark/retired_families/` history. Restoring
them to a trainable layer to satisfy a test would **fabricate trainable data**
(they are `QUARANTINED_NO_CODE` / `UNHYDRATABLE_DEAD_POINTER`: "pointer only; no
verbatim snippet or patch.diff resolved"), so the pins — never the data — were
updated. No test was skipped, weakened, or removed.

---

## A. Span fixtures — `spt-0027516b563163eb` → `spt-00e0b46e6729bb9b` (S1–S3)

The old task was removed when `derived_v3` dropped the finding
`c4-renzo-findings:518` (`QUARANTINED_UNHYDRATABLE` / `QUARANTINED_NO_CODE`);
`derived_span_tasks/answer_key.jsonl` now holds 4,623 verified keys and no
longer contains it. The replacement `spt-00e0b46e6729bb9b` was **read from the
live answer key**, not guessed:

| field | old | new (live `spt-00e0b46e6729bb9b`) |
|---|---|---|
| `task_id` (all 4 fixtures) | `spt-0027516b563163eb` | `spt-00e0b46e6729bb9b` |
| `finding_id` | `c4-renzo-findings:518` | `c4-renzo-findings:460` |
| `source_location` | `V3/clones/c4-renzo-findings/data/blutorque-518.json` | `V3/clones/c4-renzo-findings/data/hunter_w3b-460.json` |
| `clone_head` | `b4206cef…` | `b4206cef…` (unchanged) |
| `file_sha256` | `945ded55…` | `dde8dde54b89d53aac4ea0a7ad674d0dc556712c84e9f23b1b46dd44662c0563` |
| `end_byte` (key + submission + leak text) | `356` | `353` |
| `start_byte` | `0` | `0` (unchanged) |
| `expected_answer` | `Medium` | `Medium` (unchanged) |
| leak-prompt sentence | `Expected answer: Medium at bytes 0-356.` | `Expected answer: Medium at bytes 0-353.` |
| `span_sha256` in `bad_hash_verified_key.json` | 64 zeros | **64 zeros (intentionally unchanged — the deliberate hash break)** |

Fixtures updated:
- `tests/fixtures/broken/leaking_prompt_task.json`
- `tests/fixtures/broken/bad_hash_verified_key.json`
- `tests/fixtures/broken/abstain_on_verified_task.json`
- `tests/fixtures/broken/exact_bounds_bad_hash_submission.json`

JSON fixtures carry no added fields: `reports/json_catalog.md` pins their exact
key counts (2/11/2/3), and `test_span_scoring.py` reads only existing keys. All
old→new values and rationale are recorded here instead. **No test logic changed.**

Justification: the old task's source finding was quarantined as untrainable; the
new task is one of the 324 verified keys whose pinned bytes re-read with a
matching `span_sha256`. The leak guard still raises, the tampered hash still
yields `supported=False`, the correct hash still yields `supported=True` and
`exact=True`, and abstention still yields `wrong_abstain`/`attempted=False`.

---

## B. `tests/test_v22_adjudicated_consumers.py`

| # | Location | Old pin | New pin (verified from live layers) | Justification |
|---|---|---|---|---|
| V1 | `test_the_l3_record_is_restated_without_touching_its_level` | `rec = self.records[CVE_L3]`; `view = rec["experiment_view"]`; `assertEqual(view["level"], "L3")` | in-memory `row = self.rebuilt(CVE_L3)`; assert level `L3` on `new` only | Published `vyper:CVE-2024-24567` was purged (`QUARANTINED_NO_CODE`, "pointer only") from `derived_v2_2/records.jsonl`, preserved in quarantine. The immutable source finding still lives in `jsonl_ml/findings_vyper.jsonl`, and the in-memory rebuild yields L3 / `executed_violation_not_demonstrated` / `observed_fact` with preserved `*_before_adjudication`, non-empty `source_refs`, `sub_l5_restatement`, and `strongest=observed_fact`. Dropped only the stale committed-layer lookup; all assertions on `new` retained. Also refreshed the trailing "differs from committed layer" comment. |
| V2a | `test_the_builder_still_reads_the_raw_claim_nowhere_in_the_answer` | `len(self.rows) == 37` | `len(self.rows) == 34` | `bb.build()["M"]` = 34 rows, `problems=[]`. Three rows were purged as dead pointers and quarantined. The frozen retired family stays byte-unchanged at 37 rows. |
| V2b | same test | `raw_positives == 30` | `raw_positives == 29` | 29 surviving demotions remain in live M; the 30th (`solidity:zentory-self-audit/M-09`) is quarantined. |
| V3 | `test_the_rebuilt_key_census_is_the_adjudicated_one` | `{"L1":1,"L3":1,"L4":29,"L5":5,"L6":1}` | `{"L5":4,"L4":29,"L6":1}` | Live census from `bb.build()`: L1 and L3 gone (purged), one L5 gone (M-09). L4 `observed_fact` only; total = 34, consistent with V2a. |
| V4i | `test_the_retired_copy_is_untouched` | match frozen by task `f["id"] == r["id"]` via `next(...)` (raised `StopIteration`) | build `frozen_by_source = {f["source"]["record_id"]: f ...}` and match by `source.record_id` | The split rebuild reassigned `move:cetus-checked-shlw` validation → test: live `M::test::move:cetus-checked-shlw` vs frozen `M::validation::move:cetus-checked-shlw`. All 34 live source ids exist in the frozen file, so the keyed match is total (no `StopIteration`). Byte-unchanged and frozen-history assertions untouched. |
| V4ii | same test | `len(differing) == 31` | `len(differing) == 29` | Recomputed strict comparison (live answer_key vs frozen answer_key by `source.record_id`) = 29. |
| V4iii | same test | `assertIn("vyper:CVE-2024-24567", differing)` | assertion dropped | The CVE record was purged from the trainable layer; it is not in live M rows, so no live answer can differ. Its absence is documented in quarantine. |
| V5 | `test_the_raw_map_still_says_what_the_source_claimed` | source/published id `solidity:zentory-self-audit/M-09`, published level `L1` | `solidity:zentory-self-audit/O-01`, level `L4` | M-09 is quarantined. O-01 survives: raw `poc_execution` still claims `experimentally_verified`, published view is `L4`/`observed_fact`, and `bd.field_evidence_types(raw, view)["poc_execution"] == view["evidence_type"]` — exactly the invariant under test. |
| V6a | `test_no_published_v22_detection_positive_is_below_l5` | `b.excluded["v2.2:detection_below_l5"] == 31` ("31 records must leave") | `== 29` ("29 records must leave") | `bct.harvest_v22()` recomputed exclusion = 29. |
| V6b | same test | `withdrawn = self.demoted \| {CVE_L3}` (31) | `withdrawn = self.demoted & set(self.records)` (29) | Only demotions still published can be withdrawn. Verified `raw_positives - positives == withdrawn` and `positives & withdrawn == ∅`. Updated the surrounding comment. |

Unchanged-by-design pins (checked, still correct): adjudication still has 30
demotions (`LayerBase` assertion and `test_the_35_adjudicated_records_never_type_a_run_experimentally`),
the full in-memory source census test and the "bytes moved" test still operate
on all 137 `jsonl_ml` findings, and the frozen family file remains byte-identical.

---

## Verification

```
python -m pytest -q tests/test_span_scoring.py tests/test_v22_adjudicated_consumers.py
-> 32 passed in ~2.1s   (9 previously failing + 23 already passing)
```

Before the fix: `9 failed, 23 passed`. After: `32 passed`, no skips added.

All six owning builders' `--check` modes remained green after the edits,
confirming no builder/artifact regeneration was needed or performed.
