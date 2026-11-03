# reNFT M-01 / M-08 — L6 recovery record

Both findings were `l6_partial_two_revision_evidence` because the vulnerable and
fixed runs compiled **different test bytes**: the mitigation's own regression
test reaches its fixtures through a chain (`BaseTest → BaseEngine →
OrderCreator → OrderFulfiller → BaseProtocol → AccountCreator`) that changed
between the two revisions, and the per-side overlay sets rewrote its imports
differently. A run of two different tests cannot show that the outcome
difference is a property of the protocol, so the level was correctly withheld.

## What now runs

One authored, deterministic test per finding, byte-identical on both sides.
It uses only APIs present in both revisions and reconstructs the finding's own
attack shape; it does not modify or replace production code.

| Finding | Harness (published) | sha256 |
|---|---|---|
| M-01 | `harness_authored/renft/2024-01-renft__M-01.t.sol` | `04bd65db5cfa45cbdffe2d677fbf117fa1894d9f3532143e5010d080c917ecf8` |
| M-08 | `harness_authored/renft/2024-01-renft__M-08.t.sol` | `5ac31b60744de4b3ecf8bd2904f0a979e1ca5a25295e9f7113f57a7e3388faed` |

Per-run harness digest (the same value on both sides, which is the L6 evidence):

- M-01: `7dc701bf308da0dd1e85f708acd977524bff41c2b9200186402b9091d9815f34`
- M-08: `cf806e6712655ecbdeae8c40cbc74ca9da4100ce298d6ff84eef4e14a71885bf`

## Revisions and commands

| Finding | Side | Commit | Command | Outcome |
|---|---|---|---|---|
| M-01 | vulnerable | `3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291` | `forge test --json --match-path test/vlun_poc/vlun_renft_m01_partial_transfer.t.sol -vv` | **FAIL** `GuardPolicy_UnauthorizedSelector(0xf242432a)` |
| M-01 | fixed | `45ef41123b65d67b7f83cad8bc9d35917b9da30f` | same command, same bytes | PASS |
| M-08 | vulnerable | `3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291` | `forge test --json --match-path test/vlun_poc/vlun_renft_m08_destructive_burn.t.sol -vv` | **FAIL** `next call did not revert as expected` |
| M-08 | fixed | `fb8013111b57c1e09482fb3193db58cb892229e9` | same command, same bytes | PASS |

Assertion-level evidence:

- M-01 vulnerable failure is the guard rejecting a transfer of the **unrented**
  part of a partially rented ERC-1155 id (`0xf242432a` =
  `safeTransferFrom(address,address,uint256,uint256,bytes)`). That is the
  claimed freeze, not a setup or unrelated failure. The fixed guard compares
  the amount leaving the safe against the rented amount and allows the call.
- M-08 vulnerable failure is `expectRevert` not firing: the guard let the safe
  burn a rented ERC-721, i.e. the destructive call executed. On the fixed
  revision the same call is rejected with
  `GuardPolicy_UnauthorizedSelector(0x42966c68)`.

Toolchain: forge 1.8.3 (`cae51ad458f6abb64852b7709eb784352429825d`), solc
0.8.22 selected by the repository's `foundry.toml`, Python 3.12.10.

## Revision-specific source dependencies (reviewed, not harness)

These are the repository files the test reaches indirectly; they are expected
to differ where the protocol or its fixtures changed. Git blob ids:

| File | vulnerable 3ddd3245 | M-01 fixed 45ef4112 | M-08 fixed fb801311 |
|---|---|---|---|
| `src/policies/Guard.sol` | `a0a565a1` | `024c918b` | `06e3b7c0` |
| `src/libraries/Errors.sol` | `5625d185` | `cc21c672` | `d581fc79` |
| `test/BaseTest.sol` | `39befd4f` | `39befd4f` | `39befd4f` |
| `test/utils/GnosisSafeUtils.sol` | `45196a56` | `005acfd7` | `45196a56` |
| `test/fixtures/engine/BaseEngine.sol` | `13ce9f7c` | `13ce9f7c` | `13ce9f7c` |
| `test/fixtures/engine/OrderCreator.sol` | `6cf60505` | `6cf60505` | `6cf60505` |
| `test/fixtures/engine/OrderFulfiller.sol` | `d61448a1` | `d61448a1` | `d61448a1` |
| `test/fixtures/protocol/BaseProtocol.sol` | `ce08a5f6` | `ba642cb3` | `ce08a5f6` |
| `test/fixtures/protocol/AccountCreator.sol` | `95a0609c` | `d1e92fd9` | `95a0609c` |
| `test/fixtures/protocol/Protocol.sol` | `069224d3` | `e6fe4ed0` | `17007fc7` |
| `test/mocks/tokens/standard/MockERC1155.sol` | `a83cc76c` | `b592db88` | `b592db88` |
| `test/mocks/tokens/standard/MockERC721.sol` | `b77b435a` | `c03560c4` | `c03560c4` |

Why the fixture differences do not explain the observed polarity:

- M-01 fixed: Protocol/AccountCreator/BaseProtocol changes are the mitigation
  branch's fixture reorganisation (`TokenCreator`, admin whitelisting). The
  authored test does not use those added APIs; it uses `createOrder`,
  `withOfferItem`, `finalizeOrder`, `createOrderFulfillment`,
  `finalizeBaseOrderFulfillment` and the fixture token arrays, all present
  unchanged in `BaseTest`, `BaseEngine`, `OrderCreator`, `OrderFulfiller`.
- M-08 fixed: every fixture file the test reaches is **byte-identical** to the
  audited revision except `test/fixtures/protocol/Protocol.sol`, whose
  difference is the added `_performAdminDuties()` (whitelisting required by the
  fixed `Create` policy). The mocked ERC-721 changes only make `mint(address,
  uint256)` and inherited `burn` available; the test uses `mint(address)` and
  the burn selector, and the guard decision is taken before token code runs.

## Artefacts

Per-side `result.json`, `stdout.txt`, `stderr.txt` (empty), `stdout_human.txt`
(vulnerable), `command.txt`, and the published harness are committed under
`experiments/2024-01-renft__M-01/{vulnerable,fixed}/` and the M-08 counterpart.
Hashes are recorded in `reports/verified_experiments.json` and rechecked by
`tests/test_l6_evidence.py::TestRecoveredRenftClaims`.

The previous partial attempts are preserved, unchanged, under
`experiments_superseded/2024-01-renft__M-0{1,8}/{vulnerable,fixed}/`; they are
outside the `experiments/*/*/result.json` scan and are not evidence for any
current level.

## Reproduce

```
git clone https://github.com/re-nft/smart-contracts.git
git -C smart-contracts checkout <commit>
git -C smart-contracts submodule update --init --recursive
mkdir -p smart-contracts/test/vlun_poc
cp harness_authored/renft/2024-01-renft__M-01.t.sol \
   smart-contracts/test/vlun_poc/vlun_renft_m01_partial_transfer.t.sol
forge test --match-path test/vlun_poc/vlun_renft_m01_partial_transfer.t.sol -vv   # in smart-contracts
```
