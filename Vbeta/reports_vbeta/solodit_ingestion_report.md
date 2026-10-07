# Solodit ingestion report (source: solodit-harvest)

Method: 193 Firecrawl listing pages (1,926 HIGH+MEDIUM cards, 100% URL
coverage) + **734 detail pages** scraped verbatim to `nextdata/*.md`
(2026-10-07; 614 pages this session spending 604 credits, 24 banked;
bulk log `nextdata/_bulk_crawl.log`). Harvested by
`Vbeta/scripts/harvest_solodit.py` (deterministic, stdlib-only) into
`Vbeta/solodit_candidates.json`. Scrape artefacts (`.firecrawl/`,
`nextdata/`) stay untracked, referenced by path — same pattern as
`V3/clones/`.

## Source manifest / counts

- Registered source: `solodit-harvest` (tier 2, mirror; auditor originals
  canonical; `G0-mirror`).
- Candidates: **733** harvested from 734 files (**1 rejected**: file 0402,
  duplicate of `cyfrin-codehawks:stablecoin-h-03` — same CodeHawks finding
  mirrored on Solodit; skipped, never double-admitted).
- Earlier 31 stub files: all rescued with real content this session.
- Admitted records: **733** (27 IMPORT with severity+status observed —
  incl. migrated 0001; 706 IMPORT_AS_UNVERIFIED with title+link).
- Levels: L0 682 / L1 51 (dedicated stepped/code PoC sections only;
  samples spot-verified, incl. a forge-test PoC).
- Languages (majority-extension vote, chrome excluded): solidity 607,
  go 24, move 20, rust 15, cairo 2, vyper 5, unknown 109. Ecosystems only
  on explicit chain mention (conflict/silence → unknown).
- Split: whole source → train (by-source rule; no source spans splits).
  Skew noted: train 746 / validation 34 / test 2.

## 0001 migration (user-contributed → harvested)

The interim operator-authored withdrawal-queue row matched
`0001-…pearprotocol-vault…md` verbatim. It was retired and replaced by the
harvested row with real provenance — severity corrected Critical →
**High Risk** (published value), status **Fixed.**, code location
`src/PearVault.sol @ f681d7c…`, Solodit issue URL + Shieldify report link.
No `user_contributed` rows remain (gate-enforced).

## Rejection / exclusion report

| Excluded | Reason |
|---|---|
| 1 duplicate (0402) | same finding already admitted; link recorded in harvest stats |
| 1,192 unscraped issues | credits exhausted (24 banked); queued behind resume script |
| full Description prose | METADATA_ONLY: ≤200-char marked excerpt kept in `extra`, full text one hop away in `nextdata/` |

## Duplicates

- No duplicate cids (harvester fails loudly on collision).
- One cross-source duplicate found and excluded (0402, see above).
- Cross-layer note: harvested Pashov-auditor rows are finding-level where
  PRESENT V3 holds report-level pointers — different granularity, kept.

## Taxonomy / proof / patch accounting

- Taxonomy: `unknown` on all 733 (no class observed; never forced).
- PoC: 51× L1, 682× L0; 0× L2+.
- `recommended_fix_observed`: first-sentence excerpt where a Recommendation
  section exists; `verified_patch`: false everywhere; team responses kept
  verbatim as status only.

## Validation results

- `validate_vbeta.py`: 0 critical failures (incl.
  `operator_rows_stay_unverified_L0` — vacuously true post-migration).
- `tests/test_vbeta.py`: TestSoloditHarvest (volume, migration, PoC, tasks).
- `check_manifests.py`: 844/782/12 reconciled; U 673 / V 782 tasks resolve.
- PRESENT isolation: sentinels unchanged; Vbeta writes confined to `Vbeta/`.
