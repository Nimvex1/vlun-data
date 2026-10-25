# CHANGELOG (release log — append-only, newest first)

## Remediation — baseline-drift repair, reproducibility hardening (2026-10-25, unreleased)

- **v2.2 split-pointer drift repaired (37 records).** Commit `cb6a2a8` added
  `bytes` to experiment artefacts without rebuilding `splits_v2_2/`; every
  experiment-bearing record's `record_sha256` went stale and the K-Q rebuild
  refused to build. Split assignment is deterministic and unchanged (0 rows
  move). Regression net: `tests/test_v22_split_pointers.py`, and both owner
  builders' `--check` modes now byte-compare against committed bytes.
  `benchmark/manifest.json`'s `families` array also gained the F-extension
  entries it was missing. Full trace: `docs/EVIDENCE_LEDGER.md` E-2/E-3/E-15.
- **Grader repository resolution no longer needs a local clone.**
  `prove_grader._repo_url` used to materialise the reNFT registry (reading
  `work/wt/renft-smart`) and crash with `FileNotFoundError` instead of the
  documented hard failure; registered findings would have hit
  `AttributeError` on the `repo_key` shape. Resolution is now static
  (`run_verified_experiments.declared_repo_url`), assertions untouched,
  two regression tests added (E-4).
- **Published baselines are now reproducible on every supported Python.**
  CPython 3.12 changed builtin `sum()` accuracy; macro-F1 aggregation
  differed by 1 ULP across the 3.10–3.13 matrix. All metric float
  aggregation uses `math.fsum` now — the committed report bytes are
  unchanged (E-7).
- **JSON catalog covers the committed corpus only.** Two untracked
  machine-local holdout answer keys had been hashed into
  `reports/json_catalog.json`, making `catalog-current` fail on every fresh
  checkout. The keys are declared machine-local in `.gitignore` and the
  scan is `git ls-files`-based (775 → 774 entries) (E-5).
- **Reproducibility report renders on a fresh clone.** The gate's
  machine-independent counts are committed as
  `reports/reproducibility_checks_summary.json`; the per-check PASS/SKIP
  split stays machine-local. `build_repro_report.py --check` no longer
  depends on having run the gate first (E-8).
- **F-extension scoreability reconciled in the README** (no labels changed):
  F-A is 9 of 458 rows fully assessed (per-axis scoring) and F-B is 554
  three-class pairs (184/121/249), both scored by
  `scripts/score_f_extension.py`; the table's `Scorable 0` is scoped to the
  headline exact-match projection (E-6).
- **Quality documentation added** (authored, not generated):
  `docs/TASK_CONTRACTS.md` (what every task measures),
  `docs/QUALITY_CHECKLIST.md` (phase status, before/after, separate
  assessments, blockers with owners), `docs/EVIDENCE_LEDGER.md` (every
  finding with method and remedy), `docs/HANDOFF.md` (blinded IAA study +
  licence-clearance packages). OPEN blockers: family A's 14
  contradictory-gold input groups (E-1), V4 table-of-contents extraction
  (E-9, ≥1,971 rows re-measured), IAA and licence clearance (BLOCKED on
  humans), AI-export audit (assets absent).

## Remediation — global integrity roll-up (2026-10-19, unreleased)

- **Two roll-ups added.** `reports/remediation_before_after.{md,json}` states, per spec
  item, what the number was before and after and which claims were *retracted instead of
  fixed* — the 331-negative conflation, "corroborated duplicate = false positive", "every
  withheld citation keeps a sha256", METADATA_ONLY read as legal clearance,
  "contamination-proof", the intra-contract 71 label, and the null `forge_reason`.
  `reports/quarantine_report.{md,json}` collects the 11 groups that did not survive
  verification rather than leaving them scattered: split quarantine 2/2/63, V4 duplicates 2,
  extraction errors 36, PoC re-run blockers 56, V3.2 recovery blockers 9, non-EVM blockers
  27, inconclusive experiments 2, and 12,416 withheld pointers.
- **14 more freshness gates** are now in `scripts/run_gates.py`
  (`rejection-corpus-current`, `negative-stats-current`, `rejection-consistency`,
  `prove-split-current`, `rights-consistency`, `v4-licensing-current` plus the 8 layer
  gates listed above and `quarantine-report-current`). Generated reports can no longer be
  hand-edited without a gate going red.
- **Reproducibility gap closed.** `reports/v3/validation_v31.json` used to embed a live
  `git status` snapshot, so the committed gate artefact differed per checkout. The snapshot
  moved to the git-ignored `reports/v3/validation_v31_worktree.json`, and the writer now
  emits `ensure_ascii=False` so the file equals the canonical redump
  `check_reproducibility.py` §7a compares against. The committed report is byte-stable.
- **Attempt-recording test corrected.** `test_attempts_never_write_at_the_run_root` asserted
  an untracked-only worktree, which stopped being meaningful once the attempt dirs were
  staged. It now accepts an addition in either state (`??` or `A `) and adds a
  `git diff --name-status HEAD` guard that rejects any modified, deleted or renamed tracked
  artefact under `experiments_v3/` — the invariant it always claimed to test.
- **Local tooling caches excluded.** `graphify-out/` and `.opencode/` were git-ignored; they
  had injected 388 non-dataset files into the JSON catalog. Catalog now covers 759 files.
- **Verification run at this checkpoint.** `python scripts/run_gates.py`: 41 gates, 41 pass,
  0 fail, 0 skipped, exit 0. `python -m unittest discover -s tests -t .`: 390 tests, OK.
  `python scripts/check_reproducibility.py`: 19 checks, 17 pass, 0 fail, 2 skipped
  (`skipped_no_network`: pin resolution and the network build stages — recorded as skipped,
  never as success).

- **Two pipeline defects found by running the whole build, both now guarded.**
  `build_all.py` re-runs every generator, and that surfaced what per-layer freshness
  gates cannot see:
  * `check_leakage.py --emit splits_v2` is **not idempotent**. Against splits that were
    already post-processed it measures 0 near-duplicate and 0 semantic cross-split pairs,
    so its next emit would replace the 63-row `splits_v2/quarantine.jsonl` with an empty
    file (`sha d2f25d75… -> e3b0c442…`, measured 2026-10-19). The published quarantine is
    reproducible only from pre-emit splits.
  * `benchmark/manifest.json` is written by two builders in sequence; the A-J pass rebuilt
    the dict from scratch and deleted the K-Q entries, and because retired entries were
    carried only from that same file the retirement bookkeeping could not be recovered —
    six retired families disappeared on the second full build.
  Fixes: the A-J builder now carries entries it does not build
  (`vlun.carry_foreign_task_entries`) and both builders **raise** rather than silently
  drop a retired entry; `build_all.py` snapshots the published split/derived layers before
  each stage, restores any layer a stage rewrote, records it in
  `build_all.json:canonical_layer_rewrites_blocked` and exits 1, with
  `--allow-canonical-rewrite` as the explicit migration path.
  `tests/test_canonical_layer_guard.py` (9 tests) fails on the old behaviour — including
  the case where the guard only logs the rewrite instead of restoring the bytes. Verified:
  the two benchmark builders now reproduce `benchmark/manifest.json` byte-identically with
  all 17 families present.

## Remediation — execution density, new layers and held-out proof (items 6, 7, 9–11, 14, 16; 2026-10-19, unreleased)

- **Item 6, execution density.** `derived_poc_queue/triage_queue.jsonl` queues every
  exploit candidate by layer (155 v1/v2.1 records, 891 V3.1 PoC-bearing rows, reported
  separately rather than summed); 8 of the 155 are eligible under the current standard and
  27 were attempted, producing 56 recorded runs from 45 distinct sandboxed invocations
  (41 compile failures, 13 blocked, 1 inconclusive, 1 claim reproduced, 0 executed without
  impact). L6 awarded by this campaign: 0 — no fixed-revision leg was executed. The 500+
  stretch is reported as missed with the per-record blocker that caused it, not closed by
  relabelling; `reports/poc_execution_density.json` keeps unique records and total runs as
  two separate numbers.
- **Item 7, blocked-run recovery.** 9 new attempts across the 4 blocked V3.2 runs. Prisma
  reached L4 by forking the block before the attack transaction instead of replaying the
  historical transaction (the EIP-7623 gas floor is a rule change, and the attempt says so);
  gamma's blocker was corrected from `archive_state_unavailable` to a PoC that reverts on a
  fork whose archive state **is** served; the two BSC runs stay blocked on pruned 2021/2023
  state. Every attempt records provider, fork block, hardfork, solc, remappings, submodule
  SHA, log hashes, `scope_change` and `impact_check`. No canonical level was promoted by the
  recording script.
- **Item 9, non-EVM pilot.** `scripts/nonevm/` adds 5 platform adapters; 30 non-EVM
  candidates produced 76 runs, 49 executed against a named assertion, 11 reproduced their
  claim and 2 records reached the L6 ceiling (CosmWasm `Uint*_pow`/`Int256::MIN` wrap
  reproduced on the affected pins, blocked on the fixed pins, with 8 recorded cases where
  the advisory's own "regardless of overflow-checks" wording does not hold). Aptos and
  Solana/Anchor report `toolchain_missing` with the exact install command rather than
  pretending to run. `reports/nonevm_landscape.md` compares against PoPoC, PoCo, EVMbench
  and SB-Curated and does **not** claim a unique multi-VM executed corpus.
- **Item 10, evidence-span scoring.** `reports/evidence_span_audit.json` counts the V3.1
  preview (12,504 rows): 7,037 carry a resolvable span, 1,807 a page/line pointer, 12,504 a
  verified source ref, and only 1,074 spans can be hash-verified from pinned bytes — so
  11,430 tasks expect abstention. `derived_span_tasks/` is an open-key scorer (the manifest
  says so and why), answer/exactness/support/abstention are scored on separate axes, and the
  published scores are mechanical baselines, explicitly not a model result.
- **Item 11, API-sibling tasks.** 229 cross-repository sibling call-site pairs were built
  from the pinned sources and re-read by an independent reviewer, admitting 221 tasks and
  8 hard negatives with group-aware splits; 6 shared pinned files straddle splits and are
  disclosed rather than claimed away. Fixing this also exposed a reviewer bug: it compared a
  recorded *function declaration* line against the *call-site* line, which rejected every
  honest pair; the check now verifies the declaration line and the enclosing body range.
- **Item 16, root-cause taxonomy.** `taxonomy/root_cause_v1.jsonl` is a versioned
  project-local closed vocabulary of 31 entries (23 assignable leaves) built by adjudicating
  the 40 candidates — merges, splits and rejected labels are logged; 418 records assigned,
  98 left unlabelled, evidence-level floors per leaf. The brief's SWC registry URL 404s, so
  the mapping was frozen against the registry snapshot the gate checks and 5 leaves are
  explicit `no_map`. It is not described as a community standard.
- **Item 14, agreement study.** `annotation/iaa_v1/` ships the protocol, the guide, a
  seeded 300-row stratified sample and three blank templates. `reports/iaa_status.json`
  reports `measured: false`: no human annotations exist, none were invented, and the
  statistics module refuses to emit a number without two distinct human annotator ids, so
  LLM self-consistency cannot be reported as inter-annotator agreement.
- New gates: `poc-triage-current`, `poc-attempts-current`, `v32-attempts-current`,
  `span-audit-current`, `span-tasks-current`, `span-scoring-current`, `taxonomy-current`,
  `root-cause-assignments-current`, `iaa-sample-current`, `iaa-stats-current`,
  `api-siblings-current`, `sibling-review-current`, `remediation-report-current`. Each
  compares a committed artefact against a regeneration, and the new tests fail on
  deliberately broken fixtures.

## Remediation — rights, redistribution and the V4 licence contradiction (item 5, 2026-10-19, unreleased)

- `V4/licensing.json` records what each V4 source actually declares about its own
  content and what this project therefore does with it: Halborn and CoinFabrik
  publish no licence file (absence of a grant, not a permissive default), and Oak
  Security states CC BY-ND 4.0, whose No-Derivatives term is the more restrictive
  fact that `license_status: "unknown"` had been hiding on all 5,268 records.
  `scripts/reconcile_v4_licensing.py` is the versioned migration that puts that
  decision into `jsonl_v4/`, `derived_v4/` and `V4/sources.json`; it refuses to run
  if any field outside the licence set would change, keeps each row's superseded
  value, and writes `reports/v4_licensing_migration.json`. Verified after the run:
  same row count, same ids in the same order, zero non-licence field changes.
  `scripts/register_v4.py` no longer hardcodes `unknown`, so a future rebuild cannot
  reintroduce the contradiction, and a source with no recorded decision stops the
  build.
- `distribution_v1/` is the versioned distribution-safe view (rights-1.0): copied
  expressive content removed, factual metadata and independently written attributed
  digests kept, withheld content represented by pointer records carrying the source
  URL, locator, attribution, retrieval metadata and the sha256 of the bytes this
  project retrieved, plus the applied rights decision and reason. 12,900 ledger rows.
- A value filed under `immutable_reference` is now only ever a 40-hex object id.
  269 V4 findings state the vulnerable revision as an abbreviated or truncated hex
  string (202 of them seven characters); those are carried under
  `stated_reference` with `reference_kind`, because a prefix resolves only inside
  somebody else's repository and cannot pin bytes. The missing characters are not
  invented.
- `scripts/check_rights_consistency.py` is the gate: copied code or report prose in
  a distribution artefact, a licence status that contradicts itself across layers,
  missing attribution, a bad hash, a manifest that drifted, or a reuse claim the
  corpus cannot support. The residual upstream-hash gap (2,288 of 12,358 pointers
  have no publisher-recorded digest) is reported as a noted limitation, and becomes
  a failure the moment a document claims every citation keeps a sha256 — NOTICE.md
  now states which ones do.
- Historical exposure is measured separately from the current tree in
  `reports/history_exposure.md` / `reports/rights_history_exposure.json`: one
  BUSL-1.1 harness file was published verbatim in the past and remains reachable in
  history, nine further historical blobs quote Solidity, and the V4 report prose plus
  named contact mailboxes are exposure on the *current* published branch, not only in
  history. Nothing was rewritten and no history will be force-pushed without
  authorisation. 5,454 named-contact rows in the V4 layers are locators and counts
  only in every new artefact; no mailbox was copied into a new file.

## Remediation — VLUN-Prove and the private held-out split (2026-10-19, unreleased)

- `reports/prove_split_interface.json` / `.md` publish a two-revision proof task family:
  a submission is credited through `generated → compiles → executes → impact_reproduced →
  patch_verified`, where `impact_reproduced` requires the *expected assertion* to be what
  broke, and a compile or dependency failure stops the ladder instead of being relabelled
  as a failed proof. `scripts/prove_grader.py` runs the same bytes on the vulnerable and
  the undisclosed second revision, and preserves the submission, both logs and their hashes.
- The answer key (fixed revisions, expected assertions, harness digests) is written outside
  this repository and pinned by SHA-256 in the published interface; `--check` verifies the
  key has not moved rather than regenerating it. No path inside the repo may hold it, and the
  model-facing task list is leak-checked for hidden revisions, test names and assertions.
- **The ~200 executed held-out tasks are not reported as met.** The pool is
  8 tasks with both revisions executed (7 Foundry pairs from the v1 layer, 1 Hardhat pair
  from V3.2), all from 2 repositories, so it cannot be called project-held-out. The gap,
  the reason, and the unsupported Hardhat runner are recorded in the interface rather than
  closed by padding.
- Defect found and fixed at the source: `scripts/experiments.py` read a test's failure reason
  only from forge's human `[FAIL: …]` line, which `forge test --json` does not print, so every
  recorded run stored `reason: null` — an observed violation was indistinguishable from a test
  that failed for an unrelated reason. Reasons now come from the JSON entry
  (`per_test_reason`), with the human line as fallback. Recorded artefacts are evidence and
  were not rewritten; the self-check recovers the reason for 4 of 7 runs by replaying the
  preserved stdout through the grader's own parser, and says so.
- Grader self-check (validates the grader, not any model): 7 recorded runs replayed through
  the stage rules, all reaching `patch_verified`.

## Remediation — rejection evidence (2026-10-19, unreleased)

- Rejection evidence for all 458 negatives rebuilt as six independent,
  documented axes in `derived_rejections/rejection_corpus.jsonl`
  (`rejection-definitions-1.0`), with the prose definitions in
  `reports/rejection_evidence.md` and the machine-readable ones in
  `derived_rejections/definitions.json`.
- **Correction to the v2.1 line below.** "331 negatives with defensible reasons
  (127 still unknown)" counted a duplicate corroboration as if it were an
  explanation. Recounted from the records: 193 negatives are corroborated as
  duplicates of an accepted finding (the copy was redundant — that is not a
  statement that the claim is false), 9 carry a reason attributed to a named
  judge or sponsor, 1 is blocked by a gate in the cited code that removes the
  standing the claim itself asserts, **6 in total carry a technical reason the
  claim is false**, 0 had an exploit attempted that failed to demonstrate the
  violation, and 256 rest on a public label alone. The historical figure is left
  as published and marked superseded here rather than rewritten.
- Four of the eight code gates `derived/hard_negatives.jsonl` records are now
  kept as context only: one states a privileged actor ("the contract owner"), one
  gates a function the claim's actor never calls, and four say on their own face
  that the gate sits on a neighbouring function. Each blocker citation was
  re-pinned from the audited commit (branch `@main` references replaced with the
  40-hex revision, declaration line and file hash).
- `datasets/verified_negatives.jsonl` gains `carries_technical_reason`, so a
  consumer can tell a duplicate record from a refuted claim (202 admitted).
- New gate `scripts/check_rejection_consistency.py` re-derives every reported
  rejection count from the records and fails if a report restates a number the
  records do not support.

## Vbeta (unreleased beta layer, additive, isolated under `Vbeta/`)

- 7,060 candidates / 6,935 admitted records / 15 sources, incl. 733
  harvested Solodit HIGH+MEDIUM candidates (670 admitted, 63
  near-duplicate quarantines with links).
- Solodit extraction now reads both corpus layouts (structured `## Section`
  headings and inline `**Section:** value` labels) and keeps the report's own
  severity separate from Solodit's Impact axis, which had been recorded as a
  report severity on 45 rows.
- Benchmark families U (6,219 tasks) + V (6,935 tasks; U excludes 716
  admitted records whose language is `unknown`); Vbeta gate 0 critical
  failures; splits train 683 / validation 584 / test 5,668 (by-source).
- Manifest distributions are domain-named: `candidate_*` sums to the ledger
  (7,060), `admitted_*` to the admitted records (6,935).

## v3.2 — fork executions of incident PoCs

- 6 runs: 2 L5 reproduced thefts with attacker-profit evidence, 4 blocked
  at L3 (pruned RPC, unreplayable state, repo drift).

## v3.1 — normalized findings with spans + overlays

- 12,504 preview rows (7,037 new); severity explicit on 11,610, class on
  2,093, files on 5,790; gate 32/32.

## v3.0 — eighteen new archives

- 5,467 admitted records from 7,712 candidates (3,517 IMPORT, 1,934
  IMPORT_AS_UNVERIFIED, 16 IMPORT_AS_NEGATIVE, 108 corroborations);
  L0/L1 only; benchmark families R (5,467) + S (1,072); gate 33/33.

## v2.2 — five-language layer

- 137 derived records (Solidity, Rust, Move, Cairo, Vyper); 37 executed
  runs (L3 1, L5 35, L6 1); benchmark families K–Q; splits train 76 /
  validation 30 / test 31 / quarantine 2.

## v2/v2.1 — pinpoint experiments

- 9 pinpoint experiments (2 inconclusive, missing symbol recorded);
  7 patches verified effective (L6); 331 negatives with defensible
  reasons (127 still unknown) — superseded 2026-10-19: that count
  reconciled a duplicate corroboration with a technical reason; see the
  correction at the top of this file;
  71 API-sibling counterexample pairs; gate 71/71.

## v1 — original evidence layer (immutable, never rewritten)

- 264 findings, 458 negatives, 155 exploits, 38 patches from 8 Code4rena
  audits; benchmark families A–J (720 tasks A–E after quarantine).
