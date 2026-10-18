# CHANGELOG (release log — append-only, newest first)

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
