# ScaBench ingestion report (source: scabench)

Method: `datasets/curated-2025-08-18/curated-2025-08-18.json` (31 projects,
555 vulns) read from untracked `work/sources/scabench`
(`scabench-org/scabench`, MIT); parsed by
`Vbeta/scripts/harvest_scabench.py`.

## Source manifest / counts

- Registered source: `scabench` (tier 2, competitive-audit mirror;
  Code4rena/Sherlock/Cantina originals canonical; `G4`).
- Candidates: **550** harvested, **5 rejected** (4 cross-source duplicates
  of Solodit rows — bakerfi M-13, mantra M-12/M-13, initia M-04 — plus
  zero unlinked; liquid-ron/initia rows use observed repo_url + commit,
  tree URL never synthesised).
- All 550 admitted as IMPORT_AS_UNVERIFIED (no disposition field in
  schema). Split: validation (newcomer slot).

## Adjudication-thread mining

Descriptions embed the upstream debate (236/550 name a submitter; judge
90, mitigation 165, sponsor 49 mentions). Mined as attribution only:
submitter handle → externally_attributed; debate-marker presence →
observed_fact. No verdict is inferred from thread text — jest/sponsor
chatter never becomes a status.

## Language honesty

Codebase entries carry no language field and 2024–2025 contests span
EVM and non-EVM chains: all 550 rows stay `unknown` language (U-tasks
exclude them). Platform mix: code4rena 19 projects, sherlock 10,
cantina 2 (Tn Contracts, minimal-delegation — no overlap with the
Euler rows in cantina-portfolio).
