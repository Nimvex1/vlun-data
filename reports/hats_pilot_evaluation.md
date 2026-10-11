# Hats Finance Pilot Evaluation (no-write)

Status: evaluation only. No canonical dataset, manifest, label, or existing record was modified.
Scratch clones: `work/hats_pilot/` (git-ignored).

## 1. Sources and pinned revisions

| Repo | HEAD SHA | Commits | Files | Tests in repo |
|---|---|---|---|---|
| hats-finance/DAOsis-0x8ef21ecb2af12ce9cc0e475eec25f90a9622b4f4 | 05bdd42d5e1aebaa8aa34afe1668336fc90853cf | 3 | `DAOSIS/` (Solidity, JS), `report.md` | None (no Foundry/Hardhat tests) |
| hats-finance/Euro-Dollar-0xa4ccd3b6daa763f729ad59eae75f9cbff7baf2cd | c04ebafc3c6c48d612eb8df38ebd3e5b2ffa73a6 | 1 | `src/`, `test/` (Foundry), MIT | `test/EUD.t.sol`, `Validator.t.sol`, `YieldOracle.t.sol`, `InvestToken.sol` |

Environment: forge 1.8.3 (commit cae51ad4), solc 0.8.37 (auto-selected by forge; repo pins no solc version).
Repo `foundry.toml`: `evm_version = "shanghai"`, no solc pin. The repo records no submodule SHAs; `lib/` was empty in git.

Dependencies I fetched manually (repo `.gitmodules` lists them, parent repo pins none):

| Library | SHA used | Tag |
|---|---|---|
| forge-std | 0258fe875e1d8e207c1eb7175e542ea32356773c | v1.17.0 |
| openzeppelin-contracts | 54b3f14346da01ba0d159114b399197fea8b7cda | v4.9.0 |
| openzeppelin-contracts-upgradeable | f6febd79e2a3a17e26969dd0d450c6ebd64bf459 | v4.9.0 |

## 2. Execution results

### Euro-Dollar: `forge test --offline`
- Exit status: **1**. No tests executed.
- Attempts and errors, in order:
  1. Default lib (OZ upgradeable master, untagged): `Undeclared identifier __UUPSUpgradeable_init` (src/InvestToken.sol:89).
  2. OZ upgradeable v4.8.0: missing `ERC20PermitUpgradeable.sol` (file is `draft-` prefixed at that tag).
  3. OZ upgradeable v4.9.0 + OZ contracts master: `mcopy` not available for `shanghai` EVM.
  4. OZ contracts v4.9.0: `Invalid contracts specified in override list` (src/USDE.sol:87); `_beforeTokenTransfer` diamond (src/USDE.sol:20); `Wrong argument count for modifier invocation` on `Ownable(_initialOwner)` (src/YieldOracle.sol:49); `_update` not found in super (src/InvestToken.sol:114).
- Interpretation: `YieldOracle.sol` uses the OZ v5 `Ownable(owner)` constructor, while `USDE.sol` and `InvestToken.sol` use OZ v4 upgradeable APIs. No single OZ release I tested compiles the repo as committed. I did not patch the contracts to force a build, because that would test code other than the submitted code.
- Consequence: **zero** Euro-Dollar findings are execution-verified. Reproduction: not achieved.

### DAOsis
- No Foundry or Hardhat test harness exists in the repo. Nothing was executed.
- A code read confirms the `burnFrom` override in `DAOSIS/Fastrack/ERC20Token.sol` (and `NormalIDO/ERC20Token.sol`) calls `_burn(account, amount)` with no allowance check. This is an observation from source, not an execution result.

## 3. Submission classification

Judging state is not in the issue text. Labels are the only available signal. I did not infer acceptance from an issue existing.

### DAOsis (134 issues)
- Labels: `duplicate` 53, `invalid` 52, judged-looking labels (`high`, `medium`, `low`, `bug`) 29 incl. open-state issues.
- The `report.md` lists 27 items under High/Medium/Low (e.g. issue #5 burnFrom High, #25 refund Medium). It is a summary; it does not state which issues the judges accepted in a verifiable way.
- Note: #144 is labelled `Lead auditor invalid` and is titled "completation report of burnFrom() function".

### Euro-Dollar (133 issues)
- Labels: `invalid` 92, `duplicate` 33, `bug`+severity 6 (#45 High, #58 Medium, #84 Low, #47 Low, #34 Low, #41 Low), 2 unlabelled.
- Issue #45 (`bug,High`) and #58 (`bug,Medium`) are the only severity-labelled reports on the list with an explicit `bug` marker, plus #41/#47/#34 (`bug,Low`). Still not a verified acceptance record.

## 4. Candidate map (judged-looking subset, not accepted)

| Candidate | Repo / issue | Label | Contract / location | Evidence available | Execution | Status |
|---|---|---|---|---|---|---|
| Unauthorized `burnFrom` | DAOsis #5 | high | `DAOSIS/Fastrack/ERC20Token.sol:25` (also NormalIDO) | Source line, issue text | None | Unverified candidate |
| Unauthorized `burnFrom` (dup) | DAOsis #20, #23, #14 | duplicate | same | Issue text | None | Duplicate of #5 family |
| Whitelisted inflation via price arbitrage | Euro-Dollar #45 | bug, High | `YieldOracle.sol` / `InvestToken.sol` | Issue text | Blocked (compile) | Unverified |
| Blacklist bypass via deposit/burn | Euro-Dollar #58 | bug, Medium | `InvestToken.deposit` | Issue text | Blocked (compile) | Unverified |
| Price-decimal / withdraw-vs-redeem value diff | Euro-Dollar #41, #34 | bug, Low/High | `InvestToken` | Issue text | Blocked (compile) | Unverified |
| `commitPrice` public sandwich (2026 report) | Euro-Dollar #133 | none (new) | `YieldOracle.commitPrice` | Issue text by external author | Blocked (compile) | Unverified, outside judging window |

## 5. Deduplication vs VLUN

- Source URLs: no existing VLUN record references `hats-finance/*` (grep of `jsonl*`, `derived*`, `Vbeta/`, `benchmark/`: 0 hits for `DAOsis`, `Euro-Dollar`, `Eurodollar`, `hats-finance`).
- Project alias: `USDE` appears in 15 VLUN files, `burnFrom` in 25 files. These are generic terms, not evidence of overlap. Treat as **not verified duplicate**, pending a record-level comparison.
- Root-cause: `burnFrom` missing authorization is a common pattern in existing VLUN content (e.g. Solodit mirror). Overlap by class is likely; overlap by record is unknown.
- Zero exact-name matches are not sufficient, so the overlap verdict stays open.

## 5b. Counts

| Category | Count |
|---|---|
| Candidate submissions reviewed (both repos, all issues) | 267 |
| Judged-looking (severity-labelled) | 35 (DAOsis 29, Euro-Dollar 6) |
| Duplicate-labelled | 86 (DAOsis 53, Euro-Dollar 33) |
| Invalid-labelled | 144 (DAOsis 52, Euro-Dollar 92) |
| Admitted to VLUN | **0** |
| Quarantined | 0 (nothing proposed for write) |
| Rejected (explicit `invalid`/`duplicate` label) | 230 |
| Successfully reproduced (execution demonstrates violation) | **0** |
| Euro-Dollar tests run | 0 of 4 files (build failed) |
| DAOsis tests run | N/A (none exist) |

Note: the "judged-looking" count mixes labels that indicate severity with open issues. It is not an acceptance count.

## 6. Licensing

- DAOsis: no LICENSE file in the repo (only `report.md`). **Redistribution unknown**; treat as METADATA_ONLY.
- Euro-Dollar: MIT (`LICENSE`), usable with attribution.
- Issue text is contributed by third-party submitters; redistribution rights not confirmed. Use links and hashes, not copied bodies.

## 7. Remaining uncertainties

1. Actual judging outcome per issue. Labels are not a decision record. Need the Hats judging/payout record (per-issue `Lead auditor` markers and the final payout list in `report.md`) before any finding is called accepted.
2. Euro-Dollar compiles against no single OZ version as committed. A reproduction needs the original project's dependency set, which is not in the repo. Until found, every Euro-Dollar finding stays L0/L1.
3. DAOsis has no tests. Its findings can at most reach L2 (reconstructed PoC) unless a harness is written, and writing one is an author's step, not a pilot step.
4. Scope of DAOsis contracts vs the one commit: the repo has 3 commits; the contest scope may refer to a different revision. Not checked.
5. The 2026 `commitPrice` issue (#133) is outside the original judging window. Its status is unknown.

## 8. Recommendation

- Do not ingest either repo as-is.
- Hats is worth a second pass only if (a) the judging/payout record is obtainable, and (b) a version-pinned build of Euro-Dollar exists. Without (a) every record is a candidate, not an admitted finding.
- Next concrete step, no writes: fetch the judging record for DAOsis (report payout list vs issue numbers) and search for the Euro-Dollar upstream dependency set.
