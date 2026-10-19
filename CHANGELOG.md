# CHANGELOG (release log — append-only, newest first)

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
