# NOTICE — third-party source code withheld

This repository is a **redacted copy** of a Code4rena-derived smart-contract
security dataset. The reasoning, validation and exploit data are complete; a
portion of the embedded Solidity source has been removed for licensing reasons.

## What was withheld

| | |
|---|---|
| `code_context` entries removed | 1,936 |
| Solidity lines withheld | 46,070 |
| Fixing diffs withheld | 76 |

## Why

1. **Third-party dependencies.** 1,435 code snippets across 40 repositories are
   libraries the audited protocol merely integrates with — OpenZeppelin, Seaport,
   Aave, Pendle, Silo, Prisma, Morpho, Uniswap, LayerZero, Balancer, Stargate and
   others. These are not the subject of the audits and are not published here.

2. **Source-available audited code.** Two of the audited protocols are published
   under licences that permit use but **not** redistribution of the source:

   | Protocol | Licence |
   |---|---|
   | `re-nft/smart-contracts` (reNFT) | Business Source License 1.1 |
   | `baker-fi/bakerfi-contracts` (BakerFi) | Business Source License 1.1 |
   | Wildcat | BUSL-1.1 + Commons Clause v1.0 |

   Their code, and the diffs of the PRs that fixed their findings, are excluded.

## What was kept

Code from the audited protocols whose repositories declare no licence — NOYA,
Decent, Alchemix, Panoptic Hypovault and GTE Perps/Launchpad. **Note:** these
repositories carry no `LICENSE` file and GitHub reports no SPDX identifier, so
their terms are also unstated rather than permissive. If you need a strictly
licence-clean corpus, treat every `code_context[].snippet` in this repository as
a citation to be resolved from the original audit rather than as redistributable
text.

## Provenance is intact

Nothing was summarised, paraphrased or invented. For every withheld snippet the
record keeps, under `code_reference_only`:

* the source file path,
* the commit SHA,
* the line range,
* the GitHub permalink.

The corresponding `source_url` resolves the citation directly. `patch.prs_withheld`
likewise keeps the PR URL, title and merge commit SHA for every withheld diff.

## Not verified by execution

Every `poc.reproducible` and `exploit.reproducible_in_dataset` flag is `false`.
The proof-of-concept code was quoted from the published reports; none of it was
compiled or run while building this dataset.

## Upstream

Built entirely from public sources: `github.com/code-423n4/*` audit repositories
and their sibling source repositories, and the published reports at
`code4rena.com`. No other source was consulted and no source URL in any record is
synthesised.
