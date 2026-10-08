# Vbeta — new-language security-evidence layer (additive, isolated)

**Rule 1: PRESENT is read-only.** Nothing outside `Vbeta/` is created, modified
or deleted by this layer. The build script only writes under `Vbeta/` (all
paths derive from `VBETA_DIR`), and the gate warns if any PRESENT sentinel
file drifts from `present_snapshot.json`.

**Rule 2: truth over scale.** Every candidate traces to a URL actually observed
live in-session (see `fetched/receipts.jsonl`). Fields not observed are
`"unknown"` / `null` — never guessed. No exploit is executed in this pass, so
no record exceeds L1; L2–L6 require run artefacts that do not exist yet.

**Rule 3: METADATA_ONLY.** Links + hashes + attributed facts only. No
third-party report text or code is redistributed here.

## What Vbeta adds over PRESENT

| | PRESENT (v1/v2.2/V3) | Vbeta (this folder) |
|---|---|---|
| Languages | solidity, rust, move, vyper, cairo(thin), clarity(4 rows) | + **circom, noir, leo, o1js/typescript, gnark/go** (7,060 candidates, 9 languages); deepens **cairo, move, rust-solana, soroban-rust** |
| Sources | 18 V3 archives (+ v1/v2) | 15 harvested sources (11 observed + Solodit mirror + Web3Bugs + ScaBench + LISABench), none overlapping V3's 18 clones |
| Provenance | clone-HEAD + sha256 (needs ~3 GB clones) | **observation receipts** (URL + observed titles + session date; zero clones, zero gigabytes) |
| Licence wins | mostly `unknown` | `openzeppelin-cairo` rows carry observed **MIT** |
| Excluded honestly | — | `blocksec` (only a CTF fork found), `clarity`/`sway` depth (no finding-level material observed) — queued, not faked |

## Layout (all new, all inside Vbeta/)

```
Vbeta/
  README.md               this file (the layer contract)
  CREATED_AT              layer birth timestamp (isolation reference)
  present_snapshot.json   sha256 sentinels of PRESENT files + git-status at creation
  sources.json            15 sources: canonical URL, languages, verification evidence
  fetched/receipts.jsonl  one observation receipt per source (what was seen, when)
  candidates.json         hand-authored candidate facts (EVERY row cites a receipt)
  scripts/vlun_vbeta.py   constants + helpers (stdlib only)
  scripts/build_vbeta.py  sources+receipts+candidates -> jsonl_vbeta/derived_vbeta/...
  scripts/validate_vbeta.py  the gate (non-zero on critical failure)
  jsonl_vbeta/            source layer (sources.jsonl, findings.jsonl). Read-only after build.
  derived_vbeta/          records, ledger, negatives, duplicates, corroborations, manifest
  splits_vbeta/           by-source splits (no source spans splits) + quarantine
  benchmark_vbeta/        families U (language routing) + V (source-tier routing) + manifest
  reports_vbeta/          quality_report.md + validation_vbeta.json
  experiments_vbeta/      reserved (empty: nothing executed this pass)
  tests/test_vbeta.py     stdlib-only tests (run: python Vbeta/tests/test_vbeta.py)
  REMOVAL_CANDIDATES.md   you-decide prune list for PRESENT (no deletions done here)
```

## Admission rule (computed in code, not hand-stamped)

- `IMPORT` — title + severity + source link + fix/status **all observed**.
- `IMPORT_AS_NEGATIVE` — judged-rejected finding (`externally_rejected`) or a
  clean audit with zero significant findings (`verified_non_exploit`).
- `IMPORT_AS_UNVERIFIED` — title + link observed, severity or status partial.
- `IMPORT_AS_UNVERIFIED` (operator path) -- `origin: user_contributed` + severity stated: operator-authored training finding, admitted ONLY here, L0, `verified_patch` false, never `IMPORT`.
- `RESEARCH_ONLY` — report-level pointer (counts observed, no per-finding data).
- Anything else → not a row at all.

## Reproduce (writes only under Vbeta/)

```bash
python Vbeta/scripts/build_vbeta.py
python Vbeta/scripts/build_vbeta.py --check   # compute, write nothing
python Vbeta/scripts/validate_vbeta.py
python Vbeta/tests/test_vbeta.py
```
