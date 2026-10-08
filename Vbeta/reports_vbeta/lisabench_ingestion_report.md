# LISABench ingestion report (source: lisabench)

Method: `dataset/*.json` (10,185 files: Title/Content/Impact/Source/Code[])
read from untracked `work/sources/lisa-bench` (`agentlisa/bench`, MIT);
parsed by `Vbeta/scripts/harvest_lisabench.py` with `(platform, contest,
finding-id)` dedup keys.

## Source manifest / counts

- Registered source: `lisabench` (tier 2, research dataset; linked audit
  issues canonical; `G4`).
- Candidates: **5,175** harvested, **5,010 rejected** (2,709 no usable
  link, 1,870 dedup-key collisions, 415 resident overlaps, 16 no title).
- All 5,175 admitted as IMPORT_AS_UNVERIFIED (no disposition field).
  Severities verbatim (MEDIUM 1,998 · LOW 1,484 · HIGH 779 · GAS 914 —
  GAS kept as published class). Languages from first Code filename
  (solidity 5,011 + honest minorities). Split: test (newcomer slot).

## Dedup engine (mandatory, not optional)

- Within-corpus: fully-evidenced `(platform, contest, finding-id)` keys;
  keys with any `unknown` component do not participate (4,615 false
  collisions measured with the naive key — documented in harvester).
- Against residents: exact-title (247 known) plus 0.6 word-overlap guard;
  415 overlaps rejected with links.
- Near-duplicate titles across issues (e.g. Hats findings republished
  under two finding-IDs) collapse via the 0.85-Jaccard quarantine
  (63 CORROBORATION_ONLY with links).

## Licensing / content boundary

`Code[]` file CONTENT is never copied (METADATA_ONLY): filenames only,
enforced by test (SPDX/pragma/vm.prank/mapping markers asserted absent).
Finder handles preserved as attribution (`Found by` lines).
