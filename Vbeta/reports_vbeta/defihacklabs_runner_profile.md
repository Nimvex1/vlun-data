# DeFiHackLabs L4/L5 runner profile (work/sources/DeFiHackLabs @ 5a792da)

Status: **profiled, not executed**. No run artefact exists for this clone;
no L-level is claimed below. Execution is queued behind an archive-RPC key.

## Inventory (measured 2026-10-07)

- 873 `*_exp.sol` PoC contracts under `src/test/<YYYY-MM>/` (investigation
  note said 879; recount gives 873 — six names differ by glob pattern or
  were renamed upstream; the ledger, when built, counts from disk).
- Foundry-native: `foundry.toml` (shanghai, optimizer on), fork tests pin
  real mainnet addresses. No `lib/` vendored in the clone (forge-std must
  be installed at stage time; the stager records every supplied file).
- Public RPC aliases ship in `foundry.toml` (blastapi/ankr/llamarpc/nodies
  endpoints across mainnet, optimism, bsc, polygon, arbitrum, fantom,
  gnosis, avalanche, moonriver). Public endpoints are rate-limited and are
  NOT a substitute for a funded archive key (`requirements.txt` states
  this; `VLUN_RPC_URL` is unset in this environment).

## Relation to the resident V3 clone

- Resident `V3/clones/defihacklabs` (81 month-dirs at last harvest) feeds
  the v3.2 pilots in `experiments_v3/` (6 runs: 2 L5 reproduced thefts,
  4 blocked at L3 with verbatim backend errors).
- Fresh clone head `5a792da` adds post-harvest incidents (newest observed:
  Set Protocol `actualizeFee()` rounding PoC). A new-282-PoC diff ledger
  is queued behind the first execution pass, not hand-counted here.

## Staged procedure (reuses scripts/run_dhl_experiments.py conventions)

Per PoC, in temp space (never inside the clone):

1. Stage isolated forge project; PoC bytes copied verbatim; siblings
   mirrored; shared helpers supplied only from repo-own files, all
   recorded in `harness.json`.
2. `forge build` → L3 on success (`broken_original_test` otherwise).
3. `forge test` against the PoC's pinned fork block with `VLUN_RPC_URL`
   → L4 on execution; `rpc_unavailable` / `archive_state_unavailable`
   on endpoint failure (never scored as PoC failure).
4. Parse balance-log profit deltas → L5 only on observed attacker
   profit > 0. L6 never (no fixed revision executed here).
5. Write `experiments_v3/<slug>/{command,stdout,stderr,harness.json,
   result.json}` + refresh `reports/v3/experimental_proof.json`.

## Honesty paths (explicit, never reinterpreted)

- No `VLUN_RPC_URL` → stages stop at L3-compile probe with
  `environment_unavailable`; nothing above L3 is claimed.
- Pruned/unreplayable fork state → recorded with verbatim backend error
  (v3.2 precedent: 4 blocked runs kept with errors, not deleted).
- A PoC that needs live third-party state or a private key is
  `requires_external_state`, not a failure.

## Shortlist criteria for the first paid pass (when keyed)

Recent post-harvest incidents first, one per chain, preferring PoCs whose
pinned block is within archive depth of the keyed endpoint; fork-free
compile probes (L3) may run on public endpoints, fork runs may not.
