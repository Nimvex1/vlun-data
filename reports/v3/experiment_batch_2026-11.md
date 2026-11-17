# V3 PoC execution batch — 2026-11-01

Twelve compiled candidates from `reports/v3/compile_sweep.json` (`rc=0`) were
executed from the pinned DeFiHackLabs checkout
`0200ce8af03a0f9bf4ce235f4ddb9d84773fae29` with `scripts/run_dhl_experiments.py`.
Each row ran the PoC's own test function against its pinned fork block; PoC
bytes were staged unmodified and are identified by sha256 in the run's
`harness.json`. No live transaction and no private key was used.

Toolchain: forge 1.8.3 (`cae51ad458f6abb64852b7709eb784352429825d`), solc
selected per staged project (0.8.x), Python 3.12.10. Endpoints: mainnet
`https://eth-mainnet.public.blastapi.io`, BSC
`https://bsc-mainnet.public.blastapi.io` (the PoC's own literal), Arbitrum
`https://arbitrum-one-rpc.publicnode.com`.

| PoC | Chain / fork block | Result | Level | Artefact | PoC sha256 (12) | stdout sha256 (12) |
|---|---|---|---|---|---|---|
| `2026-08/USM_exp.sol` | mainnet 25716149 | pass | **L5** fund_theft, 70.83097736769771 ETH | `experiments_v3/usm/` | `4d3d572f105a` | `3b7dd262640d` |
| `2026-09/Reddio_exp.sol` | mainnet 25912200 | pass | **L5** fund_theft, 9.253090281137114 ETH | `experiments_v3/reddio/` | `5c647a795905` | `b440f3582446` |
| `2026-09/Flamincome_exp.sol` | mainnet 25990442 | pass | **L5** fund_theft, 344751.209366 USDT | `experiments_v3/flamincome/` | `11bff7043997` | `84a6abfd31b9` |
| `2026-09/SecuredFi_exp.sol` | mainnet 25914191 | pass | L4 (WBTC profit asserted, no before/after pair) | `experiments_v3/securedfi/` | `90be31df1f20` | `526f8e657039` |
| `2026-09/OMNI404_exp.sol` | mainnet 25951647 | pass | L4 (profit logged without a paired balance) | `experiments_v3/omni404/` | `f319458617a8` | `d78a03ee3bac` |
| `2026-01/MTToken_exp.sol` | BSC 74937079 | pass | L4 (no attacker balance pair) | `experiments_v3/mttoken/` | `e1c362207d7d` | `71ee5a622f67` |
| `2026-06/TOPBPool_exp.sol` | mainnet 25279891 | pass | L4 (no attacker balance pair) | `experiments_v3/topbpool/` | `b4dded8dd1b6` | `b848d06d54e3` |
| `2026-04/JuiceboxREVLoans_exp.sol` | mainnet 24917718 | pass | L4 (no attacker balance pair) | `experiments_v3/juiceboxrevloans/` | `8d1aab77454a` | `a37445864cde` |
| `2025-08/PresaleV5_exp.sol` | mainnet 23172639 | pass | L4 (no attacker balance pair) | `experiments_v3/presalev5/` | `c901e87bc6b4` | `3ba5c851293c` |
| `2026-09/YamFinance_exp.sol` | mainnet 25884984 | pass | L4 (governance effect, no profit pair) | `experiments_v3/yamfinance/` | `38a4263beb9a` | `1aa3808515ff` |
| `2026-01/futureswap_exp.sol` | Arbitrum 419829770 | blocked | L3 (`archive_state_unavailable`) | `experiments_v3/futureswap/` | `40976cd60f47` | `46b6d7b474cd` |
| `2026-03/Venus_THE_exp.sol` | BSC 86731940 | test failed | L3 (`broken_original_test`; log shows `EvmError: Revert` in `testTraceDrivenPoC`) | `experiments_v3/venus-the/` | `f708bced15fb` | `e89e8f5b0199` |

Commands are in each artefact's `command.txt`, for example:

```
forge test --match-test testExploit -vv
```

All twelve `result.json` files carry the repository URL, clone HEAD, test
return code, full per-run artefact hashes and the fork aliases; `harness.json`
also records every staged helper and the PoC hash. The proof summary is
`reports/v3/experimental_proof.json` (18 runs total: 5 L5, 7 L4, 5 blocked L3,
1 test failure).

## Why three of them stop at L4

`SecuredFi`, `OMNI404` and `YamFinance` assert their effect in the test but log
only a profit or state value, not a before/after balance pair for the same
subject. The evidence model in `scripts/v32_execution.py` refuses to turn a
single positive number, or a pair of labels describing different subjects, into
attacker gain: that is the failure mode the Flamincome run exposed before the
pairing rule was fixed. They remain executed-but-not-reproduced (L4), and their
raw logs are preserved.

`futureswap` built (L3) but the fork provider served no state at its pinned
Arbitrum block. `Venus_THE` built (L3) and the test reverted on the pinned BSC
fork; that is a PoC/test failure, not a demonstrated violation, and no level
above L3 is claimed.
