# Phase 3 fix C — protected record in canonical corpus

## Diagnosis

`tests/test_eval_leakage.py::test_the_real_corpus_carries_no_protected_record`
failed because `training/canonical/*.jsonl` carried a record that a benchmark
family holds out:

- record: `cairo:CVE-2024-45304`
- held out by `benchmark/Q_evidence_type_and_quality_rubric.jsonl:51`,
  id `Q::test::cairo:CVE-2024-45304`, `source.record_id` /
  `source.finding_id` = `cairo:CVE-2024-45304`
- the hydration rebuild moved this benchmark row to `test`; the canonical
  corpus had not been rebuilt since, so it still shipped the record as a
  `train` row in three tasks:
  `v2.2:cairo:CVE-2024-45304:detection` (detection.train.part-000.jsonl),
  `v2.2:cairo:CVE-2024-45304:language` (language.train.part-000.jsonl),
  `v2.2:cairo:CVE-2024-45304:severity` (severity.train.part-000.jsonl).

## Builder change: none required

`scripts/build_canonical_training.py` already excludes protected identifiers
correctly: it imports `protected_identifiers()` from
`scripts/build_eval_leakage_report.py` (same definition the gate uses), and
`partition()` moves any row whose `canonical_id` is in that set to the held-out
stream regardless of the row's own split label. No edit was made to the
builder — the corpus was simply stale relative to the current benchmark and
source data. The correct fix was a rebuild, not flipping the benchmark split
back to `train`.

## What I did

Ran `python scripts/build_canonical_training.py` (exit 0). It rewrote the five
`training/canonical/*.train.part-*.jsonl` shards, `training/canonical/manifest.json`,
and — as the builder's documented side effect — the non-model-visible
`benchmark/independent/canonical_holdout/` shards and manifest.

The rebuild also absorbed the other Phase 3 hydration changes that were already
present in the working tree, so the corpus shrank from 15,943 to 12,112
model-visible rows (weights are recomputed from current class counts). No source
layer, benchmark Q file, checker, test, or gate script was edited.

## Verification

- `CVE-2024-45304` occurrences under `training/canonical/*.jsonl`: **0** (was 3).
  All three exact example ids above: **0** occurrences each.
- `python scripts/build_canonical_training.py --check`: 12,112 model-visible
  examples, 5 chunks; `severity/language/detection` validation and test counts
  all **0**; 5,737 protected identifiers; 2,074 rows held out.
- `python scripts/check_eval_leakage.py` → **exit 0**. All five checks
  (`protected-evaluation-overlap`, `model-visible-corpus-hygiene`,
  `task-payload-and-key-status`, `private-answer-key-absent`,
  `canary-absent-from-corpus`) report `[ok]`. `--quiet` also exit 0.
- `python -m pytest -q tests/test_eval_leakage.py` → **23 passed, 1 failed**.
  The protected-record tests now pass:
  `test_the_real_corpus_carries_no_protected_record`,
  `test_the_gate_passes_on_this_tree`,
  `test_the_real_corpus_ships_no_held_out_partition`,
  `test_the_canonical_manifest_lists_only_model_visible_files`.
  The single remaining failure is
  `test_the_committed_report_is_current`: `reports/eval_leakage_report.json`
  and `.md` are STALE. This is report regeneration, owned by Phase 4; it was
  deliberately not done here. `check_eval_leakage.py` does **not** depend on
  the committed report being current and passes regardless.

## Files changed (owned scope)

- `training/canonical/detection.train.part-000.jsonl`
- `training/canonical/language.train.part-000.jsonl`
- `training/canonical/language.train.part-001.jsonl`
- `training/canonical/severity.train.part-000.jsonl`
- `training/canonical/severity.train.part-001.jsonl`
- `training/canonical/manifest.json`
- `reports/phase3_protected_fixes.md` (this file)

Builder side-effect (generated, non-model-visible, outside my edit scope):
`benchmark/independent/canonical_holdout/*.jsonl` and its `manifest.json` were
refreshed by the builder run.

## Observation (pre-existing, out of scope, not fixed)

`chunk_rows()` in `scripts/build_canonical_training.py` keys its output dict by
`(task, split_name)` inside a loop over `(task, original_split)` groups, so each
task's earlier split groups are overwritten by the alphabetically last one.
Of 2,074 held rows, only 853 (the `validation` groups) actually reach the
holdout shards; the `test`/`train` held rows — including this record's three
rows — are dropped rather than written. This does not cause leakage (the rows
are absent from the model-visible corpus), but it breaks the builder's stated
"nothing is deleted" invariant and is outside this fix's scope
(`benchmark/independent/canonical_holdout/`, not `training/**`). Flagging it for
the owning phase.
