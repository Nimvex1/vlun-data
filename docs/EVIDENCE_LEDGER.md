# VLUN evidence ledger — 2026-10-25 pass

## 2026-10-27 P0 integrity (this session)

Baseline: `_audit/baseline_2026-10-27.md` at commit
`6933f3f3f1a6d9270f405bf317d3d6d6de8fc7ee`. Working tree was clean; the two
pre-existing uncommitted report edits named in the plan were **not present**.

| ID | Status | Notes |
|---|---|---|
| G1 skip→pass (`build_prove_ledger.py --check` exit 0) | FIXED | exit 2 + `tests/test_gate_exit_codes.py` |
| G2 stale `extraction_errors.json` / no `--check` | FIXED | merge+state ledger; `reports-current` gate |
| G3 `--emit` emptying `splits_v2/quarantine.jsonl` | FIXED | in-script curated-write guard |
| G4 Vbeta `write_text` CRLF | FIXED | `newline="\\n"` + snapshot |
| G5 `remaining_mutable_in_source_layer` null | FIXED | producer counts jsonl/; value 453 |
| G6 gate-coverage inventory | FIXED | `scripts/gate_coverage.py` |
| README 63-row `splits_v2/quarantine.jsonl` | FIXED | live count is 2; 63 is Vbeta |

Labels, splits and answer keys were not rewritten. Family A, V4 overlay,
executable expansion and rights clearance remain OPEN (P1/P2).


Every finding: scope (file / record ids), measurement method, remedy, and
status. Historical claims from `_audit/INDEPENDENT_REVIEW.md`, `BASELINE.md`
and `improve.md` are re-measured here, never quoted. Machine-local run logs
for this pass live under `work/baseline_runs/` (git-ignored, not part of the
corpus).

Status vocabulary: `FIXED` (verified by regression test or gate),
`RECONCILED` (discrepancy traced; no label changed), `OPEN` (confirmed,
remedy scoped, not executed), `BLOCKED` (needs a human / rights / infra).

## E-0 Baseline (before edits)

- Commit `cb6a2a81665da7132663b808f76ec3eac980eefd`, branch
  `arena/a7c75743-vlun-data`, working tree clean, single-commit history.
  Local git-ignored assets: `work/` (present, sparse — `work/wt/renft-smart`
  absent) and `V3/clones/` (present as directory). `ai/` and `nextdata/`
  absent in this checkout. No ignored files were reported by
  `git status --ignored` at baseline because the checked-out ignore rules
  cover the trees that exist.
- `python scripts/run_gates.py` → **52 gates: 37 pass, 6 fail, 9 skipped**
  (skips are `skipped_no_network`: clone trees absent). Local unit suite:
  **704 tests, 2 failures + 1 error, 19 skipped** on Python 3.11.2.
- CI: run 40197010808 (push, `cb6a2a8`) red on all four Python legs
  (3.10–3.13) at `Run all gates`. CI job logs are not reachable from this
  sandbox (`results-receiver.githubusercontent.com` blocked); failure
  identity is taken from local reproduction, which matches the operator's
  reported failure list item for item.
- `scripts/validate.py` writes `reports/validation_report.json` and
  `reports/v2_1_summary.json` on every run. At baseline the failing state
  made `readme-current`, `remediation-report-current` and `catalog-current`
  disagree with the committed (passing-state) bytes mid-gate-run. Restored
  to committed bytes after diagnosis; they regenerate to identical bytes
  once validate passes again.

## E-1 Family A contradictory gold on identical inputs — OPEN

- Scope: `benchmark/A_vulnerability_detection.jsonl` (720 rows).
- Measurement (reproducible):
  `python - <<'EOF'` hashing `input` (full) and the concatenated
  `input.code.code_blocks[*].code` per row, grouping by hash, comparing
  `answer_key` sets — 2026-10-25:
  - 720 rows, **384** distinct full `input` objects, **357** distinct code
    payloads (the historical "384 distinct supplied inputs" is the
    full-input measure; both are now pinned).
  - **14 identical-input groups with conflicting labels**: 330 rows at
    code-payload granularity, 306 at full-input granularity (historical
    306 = full-input measure).
  - test split **121/147 rows without code** (exact match).
  - `distinct prompts: 1` — one fixed instruction template; the payload is
    the only variation.
- Why it matters: identical complete inputs with different gold labels
  cannot both be right under one task contract; id differences do not
  resolve it.
- Remedy (scoped, not executed): model the claim dimension explicitly in
  `input` (which finding is queried) or answer with a set-valued label; the
  14 groups are then re-adjudicated against source records. This rewrites a
  frozen family's task rows through `scripts/build_benchmark.py` and needs
  the record-level evidence audit first — it is a data-repair project, not a
  relabelling pass. Do NOT ship a leaderboard on family A until closed.
- Status: **OPEN**. Owner: dataset maintainers. Evidence needed to close:
  the 14 groups' source records read side by side with per-claim gold.

## E-2 v2.2 split-pointer drift — FIXED

- Scope: `splits_v2_2/{train,validation,test}.jsonl`, 37 of 137 v2.2
  pointers (`record_sha256`), ids = the 37 records with
  `experiment_view.present` (zentory-*, kerf-report, quantillon-report,
  move:cetus-checked-shlw, vyper:GHSA-6j9c-gvcw-74fj, vyper:CVE-2024-24567).
- Measurement: `sha256_text(json.dumps(rec, sort_keys=True,
  ensure_ascii=False))` recomputed over `derived_v2_2/records.jsonl` and
  compared with each pointer — 37 mismatches, exactly the experiment-bearing
  set. `python scripts/build_derived_v22.py` rebuilds
  `derived_v2_2/records.jsonl` byte-identically (derived layer current);
  `derived_v2_2` gained `bytes` fields on artefact entries in commit
  `cb6a2a8` ("Record artefact sizes…"), and `splits_v2_2` was not rebuilt
  after that change.
- Cross-checked: split assignment is deterministic and unchanged (0 rows
  move across splits in a dry-run rebuild); only the 37 hashes change.
- Remedy executed: rebuilt `splits_v2_2/` with its owner
  `scripts/build_splits_v22.py` (37 pointer lines rewritten; manifest and
  `reports/leakage_report_v22.json` reproduce byte-identically).
- Hardening: `scripts/build_splits_v22.py --check` now byte-compares its
  would-be outputs with the committed layer (it previously reported
  "0 problems" while never looking at committed bytes);
  `tests/test_v22_split_pointers.py` (4 tests) recomputes every pointer
  hash, checks pointer/record membership, byte-compares the K-Q rebuild with
  the committed task files, and runs both owner `--check` scripts.
- Status: **FIXED**. `python scripts/validate.py` → 78/78, 0 critical.

## E-3 K/Q benchmark rebuild refusal — FIXED (same root cause)

- Scope: `benchmark/retired_families/K_*.jsonl` … `Q_*.jsonl`,
  `benchmark/manifest.json`.
- Measurement: `scripts/build_benchmark_v22.build()` reported
  `record sha256 does not match its split pointer` × 37 → refused to build
  → `validate.py` check 44 compared empty rebuilds with 7 family files
  (44 critical failures). After the splits rebuild: `problems: []` and all
  seven families rebuild **byte-identically** to their committed files,
  including the retired rows.
- Also found: `benchmark/manifest.json`'s `families` array omitted
  `Fa_rejection_evidence_axis_vector` / `Fb_duplicate_radar_pair` although
  `tasks` carried both entries (the F-extension emitter never updated the
  array). Rewritten via `scripts/build_benchmark_v22.py` (array now
  `sorted(tasks)`); `build_f_extension.py --check` stays byte-identical.
- Hardening: `scripts/build_benchmark_v22.py --check` now byte-compares
  rebuilt rows with each family's manifest `file` path (retired included)
  and the manifest itself.
- Status: **FIXED**.

## E-4 `test_prove_split` crashed into `work/wt/renft-smart` — FIXED

- Scope: `tests/test_prove_split.py::RepositoryResolution`,
  `scripts/prove_grader.py::_repo_url`,
  `scripts/run_verified_experiments.py`.
- Measurement: `python -m unittest tests.test_prove_split` at baseline →
  ERROR `test_a_non_url_that_is_not_registered_fails_loudly`, traceback
  `FileNotFoundError: '<repo>/work/wt/renft-smart'` raised
  from `git_show` ← `build_registry` ← `prove_grader._repo_url`. Two
  defects: (1) resolution of a non-URL repository materialised the full
  experiment registry, which reads test bytes from the pinned local clone —
  a fresh checkout has none, so the documented hard failure ("cannot
  resolve a clone URL") never fired; (2) the materialised entries key the
  revision by `repo_key`, so the URL read `.get("repo").url` would have
  raised `AttributeError` even with the clone present (latent, previously
  untested path).
- Remedy executed: `run_verified_experiments.declared_repo_url()` resolves
  finding → clone URL from the static declarations with no filesystem
  access (the URL is known without materialising harness bytes — the
  module's own `_resolve_short_shas` comment says as much);
  `prove_grader._repo_url` now uses it and keeps the exact hard-failure
  contract and message. Assertions untouched; 2 regression tests added
  (registered finding resolves with `ex.worktree` guarded against any call;
  unregistered finding fails loudly without touching `work/wt`).
- Status: **FIXED** (32/32 module tests pass, 1 documented skip).

## E-5 Stale generated artefacts (README, remediation, catalogue) — FIXED

- Scope: `README.md`, `reports/remediation_before_after.{md,json}`,
  `reports/json_catalog.{json,md}`.
- Measurement: on the restored tree, `generate_readme.py --check` and
  `build_remediation_report.py --check` pass — their baseline staleness was
  induced by `validate.py` rewriting `reports/validation_report.json` with
  the 2-critical-failure state mid-gate-run (README's gate line reads that
  report). With E-2/E-3 fixed, validate writes the passing state again and
  the artefacts agree.
- Genuine catalogue defect (separate): `reports/json_catalog.json` hashed
  two **untracked, machine-local** answer-key files
  (`benchmark/independent/secondary_holdout_keys.jsonl` 2,684 rows,
  `..._exploratory_keys.jsonl` 32 rows) from the operator's working tree;
  every fresh checkout reported `entry differs`. Remedy: the keys are now
  declared machine-local in `.gitignore` (they were always documented as
  local-only and regenerable), and the catalog scan covers the **committed
  corpus only** (`git ls-files`); its `scope_note` says so. Regenerated:
  775 → 774 entries (drop 2 key entries, add the committed
  `reports/reproducibility_checks_summary.json`, update hashes repaired in
  E-2/E-3).
- Hardening: `tests/test_json_catalog.py::TestCatalogIsMachineIndependent`
  (3 tests): the keys are declared and never catalogued; a stray untracked
  JSON cannot change the catalog (`--check` stays green); the committed
  catalog lists no untracked entry. Note: the catalog is index-based — a
  **new** committed file must be `git add`ed before regenerating the
  catalog (this session staged
  `reports/reproducibility_checks_summary.json` for exactly that reason,
  without committing anything).
- Status: **FIXED**.

## E-6 F-extension scoreability vs README — RECONCILED (no labels changed)

- Scope: `benchmark/Fa_rejection_evidence_axis_vector.jsonl` (458),
  `benchmark/Fb_duplicate_radar_pair.jsonl` (554),
  `benchmark/manifest.json`, `reports/f_extension.md`,
  `reports/f_extension_baselines.json`, `README.md`.
- Measurement: the canonical counts agree everywhere they are defined:
  CI/gates report 458 records, 9 labelled F-A rows, 554 F-B pairs (184
  same / 121 distinct / 249 ambiguous) — matching
  `check_f_extension.py --check`, `build_f_extension.py --check`,
  `reports/f_extension.md` ("manifest scorable counts: F-A 9, F-B 554").
  The manifest's `scorable` (9 / 554) is **own-contract** scoreability
  (F-A: every axis assessable; F-B: three-class pair adjudication).
  The README's `Scorable 0` / `NOT_SCORABLE` came from the headline
  exact-match projection (`independent_benchmark_audit.NOT_SCORABLE`), which
  deliberately excludes both families: F-A has no single scalar label; F-B
  is scalar in shape but would move the published headline denominator
  while its pair floor is still trivial-classifiable. Two different
  measurements, one word ("scorable").
- Remedy executed (presentation only): `scripts/generate_readme.py` now
  states both numbers and both definitions in the README (per-axis: 9 of 458
  fully assessed, 449 partial; pair adjudication: 554 = 184/121/249), with
  the 0 scoped to the headline projection and links to the F scorer's own
  reports. No label, score or family status was changed. `f-extension-*`
  gates remain byte-identical.
- Status: **RECONCILED**.

## E-7 Published baselines not reproducible across Python versions — FIXED

- Scope: `reports/baselines/*.json`, `scripts/score_benchmark.py`.
- Measurement: `baseline_majority.json`'s `micro_retired.macro_f1`
  regenerates as `0.18752334805774482` on CPython 3.12+ and
  `0.1875233480577448` on 3.10/3.11 — 1 ULP apart. Root cause: CPython 3.12
  changed builtin `sum()` to Neumaier-compensated float summation;
  `macro_f1` averaged per-class F1s with `sum(scores)`. Verified:
  `math.fsum(scores)/len(scores)` reproduces the committed value exactly on
  3.11. Any "regenerate and byte-compare" gate therefore failed on the
  3.10/3.11 CI legs while passing on 3.12/3.13 — and the repo's supported
  matrix is 3.10–3.13.
- Remedy executed: all float aggregations in `score_benchmark.py`
  (`macro_f1`, `cosine`, retrieval norms) and the macro means in
  `score_f_extension.py` and `independent_benchmark_audit.py` use
  `math.fsum`. **No published byte changes**: all six baseline reports and
  the F/audit reports regenerate byte-identically on 3.11 after the fix
  (measured).
- Hardening: `tests/test_baselines.py::TestFloatAggregationIsVersionStable`
  (3 tests) pins exactly-rounded aggregation on an input where naive
  summation provably drifts (6 per-class F1s of 0.4) and asserts the
  published `micro_retired.macro_f1` value is unchanged.
- Status: **FIXED**.

## E-8 `reports/reproducibility_report.md` unrenderable on a fresh clone — FIXED

- Scope: `scripts/build_repro_report.py`, `tests/test_generated_docs.py`.
- Measurement: with the git-ignored `reports/reproducibility_checks.json`
  absent (fresh clone, or first standalone `python -m unittest discover -s
  tests`), `build_repro_report.py --check` reported STALE — the
  reproducibility row rendered "SKIPPED" instead of "19 checks". The row
  read the machine-local snapshot; the count itself is machine-independent.
- Remedy executed: `scripts/check_reproducibility.py` additionally writes a
  committed `reports/reproducibility_checks_summary.json` (counts only:
  `checks_total`, `checks_failed_critical` — no per-check statuses, which
  stay in the git-ignored snapshot); the generator's reproducibility row
  reads the summary. Report bytes change only by one prose paragraph naming
  the summary. This is also what forced the catalog/index rule in E-5.
- Hardening: `test_report_renders_on_a_fresh_clone` (snapshot deleted,
  `--check` must pass) and
  `test_the_reproducibility_counts_are_committed_and_status_free` (summary
  in the git index; no status fields).
- Status: **FIXED**.

## E-9 V4 impact fields carrying table-of-contents text — OPEN

- Scope: `derived_v4/admitted_ledger.jsonl` (5,268 rows), field `impact`.
- Measurement (2026-10-25, two predicates, both reproducible):
  - tight predicate (dot/underscore leaders or ≥3 numeric tokens with ≤6
    long words): 31 rows;
  - structural predicate (two or more (page-number, short section-title)
    pairs, e.g. `13 Description 13 Code Location 13 Example Functions 14
    Risk Level 14`, or leader pages): **1,971 rows** — i.e. the historical
    "1,218" claim is directionally right and its exact count was
    predicate-dependent; the defect is real and at least as large.
  Examples show the extraction glued a findings table of contents into the
  `impact` field (`1 =====PAGE 3===== Code Location`).
- Remedy (scoped, not executed): repair the V4 report segmentation in
  `scripts/register_v4.py` / the staged-conversion extractor (distinguish
  contents pages from finding bodies, anchor headings to the finding, keep
  impact separate), re-extract against independently annotated source
  spans, and attach versioned corrections + quarantine reasons — never
  silently overwrite the historical ledger. Field-level correctness must be
  measured against annotated spans, not nonempty-field rates.
- Status: **OPEN**. Owner: extraction pipeline maintainers. Evidence
  needed: annotated source spans for a risk-based sample of the affected
  reports.

## E-10 AI export repetition (historical `ai/` findings) — BLOCKED (assets)

- Scope: `ai/vlun_gemma4_code.json` (historical: 393 examples / 121 distinct
  code blocks) and the larger AI export (3,036 / 204).
- Measurement: **`ai/` is absent from this checkout** (documented
  local-only scratch; nothing in the pipeline reads it). The claims cannot
  be re-measured here.
- Remedy (when the export is supplied): audit repetition, title hints,
  synthetic labels, provenance and overlap with evaluation material;
  separate code-only from report-conditioned inputs; keep finding titles and
  outcome-bearing prose out of code-only inputs; give every synthetic
  example explicit provenance and assumptions; treat timestamp-based
  vesting as a context-dependent design question, not an inherent
  vulnerability; retain uncertain examples as uncertain.
- Status: **BLOCKED** (needs the operator's `ai/` export). Never treat the
  historical counts as corpus counts.

## E-11 Human annotation agreement not measured — BLOCKED (needs reviewers)

- Scope: all labelled families; especially the rule-derived gold of the
  F-extension, span tasks and family A's claim labels.
- Measurement: `scripts/iaa_statistics.py --check` → `measured=False`,
  byte-stable. The IAA sample is frozen (`iaa-draw-1.0`, n=300,
  seed=20261018, templates match) and **awaiting two independent qualified
  reviewers**. LLM self-consistency is not IAA and is not claimed anywhere.
- Remedy: execute `docs/HANDOFF.md` §1 (blinded study protocol, labels and
  adjudication rules frozen before collection, risk-based sample already
  drawn). Do not fill templates with fabricated responses.
- Status: **BLOCKED** (human reviewers).

## E-12 Rights clearance — BLOCKED (needs rights-holders)

- Scope: redistributed content vs. citation-only content;
  `NOTICE.md`, `distribution_v1/`, `Vbeta/reports_vbeta/` licence
  checklist, `scripts/inventory_rights.py`, `scripts/check_rights_consistency.py`.
- Measurement: `rights-consistency` gate passes (no contradictory licence
  state; no copied expressive content in the distribution view; V4 licence
  fields match `V4/licensing.json`). The rights-redacted distribution
  explicitly disclaims legal clearance and excludes canonical training and
  benchmark material — that remains true and unaltered. A hash, citation,
  public URL or short quotation length does not grant redistribution.
- Remedy: `docs/HANDOFF.md` §2 (outbound licence-clearance request
  package). Unresolved rights stay unresolved.
- Status: **BLOCKED** (rights-holders' permission).

## E-13 Local asset inventory (this checkout)

| asset | status | classification |
|---|---|---|
| `work/` | present, sparse (`work/wt/renft-smart` absent; `work/repos` absent) | external clones + execution artefacts, never redistributed (`.gitignore`) |
| `V3/clones/` | present as directory (manifest only tracked) | third-party report archives, never redistributed |
| `ai/` | **absent** | operator-local scratch (E-10) |
| `nextdata/` | **absent** | local-only Solodit scrape artefacts |
| `reports/reproducibility_checks.json` | machine-local snapshot | git-ignored by design |
| `benchmark/independent/secondary_holdout_*keys.jsonl` | absent (regenerable) | OPEN-KEY answer keys, local-only by declaration (E-5) |

## E-14 Benchmark validity / shortcut floors (re-measured from reports)

- `reports/independent/audit.json` + `reports/baselines/*` regenerating
  byte-identically (E-7): 1 family at PRIMARY (A), the rest EXPLORATORY /
  INVALID / retired / NOT_SCORABLE. Train-only shortcut floors are
  published per family (majority/retrieval etc.). Two families leak at
  `high` in the auditor's flags (K, L) — both retired and excluded from the
  headline. `eval-leakage` gate: no protected evaluation record, answer or
  payload reachable from the model-visible corpus.
- OPEN caveat (documented, not defect): every benchmark key is OPEN-KEY;
  pretraining contamination cannot be claimed absent without evidence. Only
  VLUN-Prove is private.

## E-15 Weak `--check` modes in v2.2 owner builders — FIXED

- `build_splits_v22.py --check` and `build_benchmark_v22.py --check`
  validated internal consistency but never compared with committed bytes,
  so the E-2 drift passed them while critical validate checks burned. Both
  now byte-compare (stale outputs listed, exit 1). Regression covered by
  `tests/test_v22_split_pointers.py::TestOwnerChecksReportCurrent`.

## Before / after (reproducible commands)

```bash
# before (baseline cb6a2a8): 52 gates, 37 pass / 6 fail / 9 skipped
python scripts/run_gates.py
#   FAIL v1-authorship (CRITICAL v2.2/splits_v2_2_pointers_resolve (37),
#        v2.2/benchmark_kq_rebuilds_from_the_records (44))
#   FAIL unit-tests (errors=1 prove_split; failures=1 baseline_majority)
#   FAIL readme-current / remediation-report-current / catalog-current /
#        benchmark-baselines-current  (all downstream of the above)
python -m unittest discover -s tests   # 704 tests: 2F + 1E

# after: see the same commands; expected
#   validate.py -> 78/78, 0 critical
#   run_gates.py -> 0 FAIL among the six repaired gates, same 9 skips
#   unittest -> 0 failures / 0 errors (skips unchanged except none added)
```

Exact before logs: `work/baseline_runs/gates_before.txt`. The after log is
produced at the end of this pass and quoted in `docs/QUALITY_CHECKLIST.md`.
