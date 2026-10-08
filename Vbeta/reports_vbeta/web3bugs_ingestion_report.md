# Web3Bugs ingestion report (source: web3bugs)

Method: `results/bugs.csv` (492 rows) + `results/contests.csv` (104 rows)
read from untracked `work/sources/Web3Bugs` (commit `fd8544e8`, MIT);
parsed by `Vbeta/scripts/harvest_web3bugs.py` (stdlib `csv` module).

## Source manifest / counts

- Registered source: `web3bugs` (tier 2, research dataset; Code4rena
  originals canonical; `G4`).
- Candidates: **491** harvested, **1 rejected** (duplicate of
  `solodit-harvest:0641-…sandwich-attack…`, caught by title-overlap guard).
- All 491 admitted as IMPORT_AS_UNVERIFIED (title + severity + link;
  no disposition field exists). Split: test (newcomer slot).

## CSV quoting fix (load-bearing detail)

The file writes `, "..."` (space before opening quote). Python's `csv`
module without `skipinitialspace=True` parses the space as an unquoted
field start and splits on inner commas — 27 rows mis-split, putting
description tails in the Reference column (27 gate failures on `https`).
The harvester sets `skipinitialspace=True`; all 491 links verified
`https://code4rena.com/reports/…` by test.

## Label discipline

`Bug Label` values (`L1`, `S6-4`, `O5`, …) are the paper's
oracle-difficulty classes, NOT severities. Stored as
externally_attributed difficulty signal in `extra`; every row's
severity_observed is "High" (all Bug IDs are H-*). Window 2021-04..2022-12
predates resident v1 scope; zero v1 name overlap confirmed.
