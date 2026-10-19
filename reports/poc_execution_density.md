# v1/v2.1 PoC execution density

Generated from `reports/poc_attempts.jsonl` by `scripts/rerun_v1_pocs.py`. Every number here is recomputed from recorded attempts.

## Candidates and attempts are different counts

- exploit records in the v1/v2.1 queue: 155
- eligible under the current standard: 5
- attemptable (a sandboxed run is meaningful): 24
- additional candidates queued from other layers (counted separately, never merged): 891
- **unique vulnerability records attempted**: 27
- **total runs recorded**: 56
- distinct sandboxed invocations: 45

## Outcomes

| outcome | runs |
|---|---|
| `blocked` | 13 |
| `claim_reproduced` | 1 |
| `compile_failed` | 41 |
| `executed_without_impact` | 0 |
| `inconclusive` | 1 |

Per unique record (last attempt wins):

| outcome | records |
|---|---|
| `blocked` | 3 |
| `claim_reproduced` | 1 |
| `compile_failed` | 23 |
| `executed_without_impact` | 0 |
| `inconclusive` | 0 |

## Blockers, as preserved data

| blocker | runs |
|---|---|
| `fixture_missing` | 9 |
| `harness_reconstruction_required` | 28 |
| `toolchain_missing` | 18 |

## Evidence levels the runs support

- `L3`: 1 run(s)
- `L5`: 1 run(s)

## Runs that reached the execution levels

- `2024-01-renft/M-11` (2024-01-renft/M-11#attempt_2) -> `L5` / `claim_reproduced`, artefact `experiments_v1_reruns/2024-01-renft__M-11/attempt_2`
  - assertion: `assertNotEq(rentalOrderTypeHash, rentalOrderTypeHashCorrect)`
  - assertion: `assertNotEq(rentalOrderTypeHash, correctTypeHash)`
  - assertion: `assertEq(rentalOrderTypeHashCorrect, correctTypeHash)`
- caveat: this campaign never executed a fixed revision, so no run here can be L6; an L5 claim also needs the assertion polarity reviewed by a human before it is promoted in the canonical layer

L6 awarded by this campaign: 0 (no fixed revision was executed under this standard).

## Stretch campaign

- target: 500 distinct sandboxed PoC/test invocations
- achieved: 45
- shortfall: 455

The 500+ stretch target was not met. The v1/v2.1 pool has 155 exploit records; only 24 of them expose a test function against a locally available pinned tree, so the campaign is bounded by the corpus, not by compute. Reruns were not counted as new work, and failures were kept as data instead of being relabelled.

