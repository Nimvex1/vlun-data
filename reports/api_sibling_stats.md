# API-sibling tasks (spec item 11) -- actual yield

Cross-repository sibling **call-site** pairs: the same upstream API used at two call sites in two audited repositories, where one is the form a confirmed finding blames and the other carries the handling it omits. Baseline: the 71 intra-contract `api_sibling_pairs` in `derived/counterexamples.jsonl`.

## Yield

| stage | count |
|---|---|
| candidate pairs proposed from the source pool | 229 |
| re-derived and reviewed independently | 229 |
| reviewed and agreed | 221 |
| admitted tasks (`derived_siblings/tasks.jsonl`) | 221 |
| hard negatives (`derived_siblings/hard_negatives.jsonl`) | 8 |
| dropped (could not be re-read from the pinned bytes) | 0 |
| v2.1 baseline | 71 |

Target of 300+ tasks reached: **no**. the pool holds 229 real cross-repository sibling call sites; 0 could not be re-read from the pinned bytes and 8 failed the contrast under the independent reader, so 221 tasks are admitted. The binding limit is the number of confirmed findings whose cited code actually contains a call to a shared upstream API, not a processing step.

## Why candidates did not survive

| reason | count |
|---|---|
| `reference:form_disagreed` | 5 |
| `vulnerable:form_disagreed` | 3 |

## Composition

| property | tasks |
|---|---|
| `externally_influenced_balance_as_source` | 179 |
| `caller_supplied_recipient` | 19 |
| `unchecked_token_move` | 19 |
| `unchecked_low_level_call` | 4 |

### By API symbol

- `balanceOf`: 179
- `transfer`: 18
- `transferFrom`: 9
- `approve`: 4
- `call`: 4
- `safeTransfer`: 4
- `safeTransferFrom`: 3

### Vulnerable-side repositories

- `Code4rena/2024-04-noya`: 124
- `Code4rena/2024-01-decent`: 48
- `Code4rena/2022-05-alchemix`: 30
- `Code4rena/2025-08-gte-perps`: 17
- `Code4rena/2024-01-renft`: 2

### Reference-side repositories

- `prisma-fi/prisma-contracts`: 46
- `balancer/balancer-v2-monorepo`: 42
- `code-423n4/2025-06-panoptic`: 42
- `silo-finance/silo-core-v1`: 42
- `code-423n4/2024-04-noya`: 12
- `code-423n4/2022-05-alchemix`: 9
- `aerodrome-finance/contracts`: 6
- `morpho-org/morpho-blue-bundlers`: 6
- `Uniswap/v2-periphery`: 5
- `pendle-finance/pendle-core-v2-public`: 5
- `Synthetixio/synthetix-v3`: 3
- `code-423n4/2024-12-bakerfi`: 2
- `Uniswap/v3-periphery`: 1

## Group-aware splits

whole vulnerable-side audited repositories are assigned to one split each, so no audited project's finding is seen twice; reference-side repositories are shared library code by construction and their straddle is measured in the hold-out audit instead of claimed away

| split | tasks |
|---|---|
| train | 126 |
| validation | 48 |
| test | 47 |

Groups: 5.

## Project-held-out audit

Grouping unit: `vulnerable_side_audited_repository`. Vulnerable-side audited repositories: 5; straddling splits: **0**.

Reference-side repositories: 13; appearing in more than one split: **8** (shared library code by construction; reported, not claimed away).

Repositories that appear only in test: `Code4rena/2022-05-alchemix`, `Code4rena/2025-08-gte-perps`

## Near-duplicate leakage audit

Pairs compared: 24310 (thresholds Jaccard 0.8, cosine 0.7).

- near-duplicate pairs: 2001, of which cross-split: 0
- semantically-similar pairs: 5954, of which cross-split: 440
- pinned files cited by more than one task: 25, cross-split: 6
- identical call sites reused across tasks: 49

## Rights decisions applied

Every item stores spans and hashes only: `citations_and_spans_only__no_source_text_redistributed`. Vulnerable-side licence classes: {"source_available_but_not_redistributable": 2, "unknown": 227}. Reference-side: {"redistributable": 103, "source_available_but_not_redistributable": 63, "unknown": 63}. Authority: NOTICE.md: much of this corpus is source-available-but-not-redistributable or ships no licence at all; this layer therefore stores spans and hashes of the pinned bytes rather than the bytes.

## Standing of this layer

leakage-audited under the recorded criteria; NOT contamination-proof. Hard negatives are real near-misses re-read from the same pinned sources, not invented contrasts. No expressive source text is redistributed: every member stores spans and hashes.

tasks.jsonl is the model-facing layer and carries no expected label; the admitted/rejected disposition lives in this report and in reports/sibling_review.json, which are separate clearly-named files

