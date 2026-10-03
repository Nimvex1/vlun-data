# NOTICE — third-party source code, and what was verified

This repository is a **redacted** copy of a Code4rena-derived smart-contract
security dataset. The reasoning, validation and exploit data are present; a
portion of the embedded Solidity source has been removed for licensing reasons.

## What was withheld from the published copy

| | |
|---|---|
| `code_context` entries removed | 1,936 |
| Solidity lines withheld | 46,070 |
| Fixing diffs withheld | 76 |

## Why

1. **Third-party dependencies.** Many cited snippets are libraries the audited
   protocol merely integrates with — OpenZeppelin, Seaport, Aave, Pendle, Silo,
   Prisma, Morpho, Uniswap, LayerZero, Balancer, Stargate and others. They are not
   the subject of the audits and are not published here.

2. **Source-available audited code.** reNFT, BakerFi and Wildcat are published
   under licences that permit use but **not** redistribution (BUSL-1.1 / Commons
   Clause). Their code, and the diffs of the PRs that fixed their findings, are
   excluded.

## What was kept, and the caveat that matters

Code from the audited protocols whose repositories declare **no licence** — NOYA,
Decent, Alchemix, Panoptic and GTE — remains in this repository, because it was
redistributed upstream. That is a deliberate, upstream decision, not a
determination that the terms are permissive.

`python scripts/fetch_sources.py` reads the LICENSE file at each cited commit and
reports what it finds. 424 of 722 derived records carry source text from
a repository that declares **no licence at all**: their terms are unstated rather
than permissive. Each is flagged at `redistribution.flag` in
`derived/records.jsonl`. **If you need a strictly licence-clean corpus, treat
every `code_context[].snippet` in this repository as a citation to resolve from
the original audit rather than as redistributable text.**

## Provenance is intact

Nothing was summarised, paraphrased or invented. For every withheld snippet the
record keeps, under `code_reference_only`: the source file path, the commit SHA,
the line range, the GitHub permalink and a sha256 of the content that
`scripts/fetch_sources.py` retrieved locally.

## What execution actually established in v2.1

v2 executed 155 PoCs with a weak criterion (any forge run) and reported 5 as "reproduced"
without recording the assertion that failed. v2.1 replaces that with pinpoint experiments:

| | |
|---|---|
| declared exploit experiments | 9 |
| verified effective patches (L6) | **5** |
| inconclusive, with the missing symbol recorded | 4 |
| experiments that modified production code | 0 (asserted per run by the gate) |
| experiments that ran against an unpinned revision | 0 (`prepare()` refuses to start) |

Every experiment directory under `experiments/` holds the harness as compiled, the exact command,
forge's per-test verdict, the observed `[FAIL: ...]` reason and a `result.json` with the artefact
hashes. `scripts/validate.py` fails the build if any L6 record lacks both legs, if any effective
patch lacks a failing vulnerable leg and a passing fixed leg, or if any experiment touched a file
under `src/` or `contracts/`.

`jsonl/` is still the original v1 layer and its `poc.reproducible` flags remain `false` — that layer
is not rewritten. Execution evidence lives in `reports/reproduction_stats.json`,
`reports/patch_verification_v2.json` and `experiments/`.

## What v2 execution established (superseded, kept for comparison)

`jsonl/` is the original v1 layer and its `poc.reproducible` flags remain
`false` — that layer is not rewritten. Execution evidence lives in the derived
layer:

| | |
|---|---|
| exploit records attempted | 155 |
| repositories that compiled | 4 of 8 |
| PoCs that demonstrated the claimed impact | **5** |
| PoCs that ran without the claimed impact | 2 |
| PoCs run but inconclusive | 8 |
| PoCs that could not be executed | 140 |

A PoC counts as reproduced only when forge reported `Success` for its test; see
`reports/verification_stats.json` for the per-record command, status and failure
reason, and `scripts/validate.py` fails the build if any record claims
experimental verification without a run artefact behind it.

## Harness modifications

To run the PoCs, `scripts/verify_pocs.py` may, and records when it does:

* install `node_modules` with `--legacy-peer-deps` (these repositories pin hardhat 2.x),
* reset the repository's **test** tree to the pinned commit,
* insert the reporter's PoC function into the test contract the report names,
* set `FOUNDRY_VIA_IR=true` (these projects do not compile without it).

In v2.1 the harness never touches a repository file at all. The experiment engine writes into a
separate overlay directory (`test/vlun_poc/`) and rewrites the overlay's own `@test/...` imports,
so `git status` shows the additions and nothing else. Where a fixture only exists in a later
revision it is supplied as an overlay file and listed per run in
`experiments/*/result.json` under `forensics`.

**Harness files are licence-gated too.** Only the tests this pipeline wrote itself are published
under `experiments/*/harness/`. A harness file copied verbatim out of reNFT is **not** published:
`experiments/*/harness/WITHHELD.json` records its path, byte count and sha256, plus the commit to
read it from, so the exact bytes that were compiled stay verifiable without redistributing BUSL-1.1
source. `scripts/validate.py` fails the build if a withheld file appears in the published tree.

No file under `src/` or `contracts/` is ever modified, and no vulnerable contract
is altered to make a PoC pass. Every modification is listed per repository under
`harness_modifications` in `reports/verification_stats.json`.

## Upstream

Built entirely from public sources: `github.com/code-423n4/*` audit repositories,
the dependency repositories their reports cite, and the published reports at
`code4rena.com`. No source URL in any record is synthesised.
