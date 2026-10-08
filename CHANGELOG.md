# CHANGELOG (release log — append-only, newest first)

## Vbeta (unreleased beta layer, additive, isolated under `Vbeta/`)

- 844 candidates / 719 admitted records / 12 sources, incl. 733 harvested
  Solodit HIGH+MEDIUM findings (21 IMPORT, 51 L1 quoted-PoC, 63
  near-duplicate quarantines with links).
- Benchmark families U (673 tasks) + V (719 tasks); Vbeta gate 0 critical
  failures; splits train 683 / validation 34 / test 2 (by-source).

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
  reasons (127 still unknown); 71 API-sibling counterexample pairs;
  gate 71/71.

## v1 — original evidence layer (immutable, never rewritten)

- 264 findings, 458 negatives, 155 exploits, 38 patches from 8 Code4rena
  audits; benchmark families A–J (720 tasks A–E after quarantine).
