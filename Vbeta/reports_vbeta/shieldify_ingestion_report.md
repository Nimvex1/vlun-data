# Shieldify ingestion report (source: shieldify-audits-portfolio)

Method: live repo table observed 2026-10-07 (168 rows / 167 IDs, 131 PDFs,
271 stars, 476 commits). 5 PDFs fetched to temp, mined with
`scripts/pdf_text.py` (readability 0.93-0.95), then deleted (METADATA_ONLY).
Only structured attributed facts entered `Vbeta/`.

## Source manifest / counts

- Registered source: `shieldify-audits-portfolio` (tier 1, first-party,
  Solidity+Rust+Move+Go; EVM+Solana+Aptos+Cosmos).
- Candidates: **33** (27 findings mined from 5 PDFs + 6 report-level pointers).
- Admitted records: **27 IMPORT** (title + severity + link + status observed).
- Reports mined: Stormrae (Jan 2026, Solana), Lido CSM (Jul 2024),
  HanaNetwork (May 2024, Cosmos/Go), Rewardy Move (Nov 2025, Aptos),
  Dinero SuperETH (Nov 2024).

## Rejection / exclusion report (quality > quantity)

| Excluded | Reason |
|---|---|
| 11 `Soon` rows (IDs 167,166,165,164,163b,162,158,152,145,125,101) | no report published = no evidence |
| 26 `-` rows without PDFs | no evidence (Jailed rescued: PDF exists in `reports/` despite `-`, kept as pointer) |
| 7 Undisclosed rows | no project, no report |
| 4 penetration-test reports (Dedprz, Hopium, AllYourBase, BeeCasino) | web2/game pen-tests, not smart-contract findings |
| 3 off-chain audits (Pear V2 offchain, CrushTrading, Colb Web2) | not smart-contract material |
| 1 Python audit (HLOS trading API) | not smart-contract material |
| ~100 remaining PDFs not mined | queued as future pointers; never upgraded without mining |

## Duplicate report

- `Beraji-KO-Security-Review.pdf` linked from **two** IDs (90 Jiko, 75
  Beraji-KO): same-file repeat, recorded, not double-counted (neither mined).
- Repeat clients (separate reports, kept distinct): Colb x9, Pear x6,
  OnchainHeroes x6, Possum x5, Harmonix x5, Multipli x4, Terplayer x4,
  Etherspot x4, Berally x3, Honeypot x3, Kanpai x3, Bankroll/Topaz/Rewardy/
  Spellborne/Shiny/Souls x2, GooseRun/Adrastea/GlueX/Ion/Yeet/GNUS/DarkMythos/
  Geode/HarvestFlow x2.
- No duplicate findings among the 27 mined rows.

## Taxonomy distribution (mined findings)

| Class | n | Confidence split |
|---|---|---|
| Access Control | 10 | high 6 / medium 4 |
| Other | 10 | medium 5 / low 5 |
| Denial of Service | 3 | high 2 / medium 1 |
| Arithmetic | 2 | high 1 / medium 1 |
| Front-running | 1 | high 1 |
| unknown (refused) | 1 | n/a (rewardy-i-02: code-quality note) |

Original titles preserved verbatim on every record; normalization never
overwrites source wording.

## Proof-level distribution

- L1 (published PoC / exploit steps in report): **5** (stormrae H-01, M-02,
  I-01, I-02; lido L-01).
- L0 (description/theory only): **22**.
- L2+: **0** (nothing executed; no upgrade of published PoCs).

## Patch accounting (recommended_fix vs verified_patch)

- `recommended_fix_observed`: present on all 27 (<=140-char factual notes).
- `verified_patch`: **false everywhere** — report ToC statuses preserved
  verbatim (`Fixed` x7, `Acknowledged` x17, `To be fixed` x2, `Will be fixed`
  x1); a team-reported `Fixed` is never experimental proof here.

## Title-leakage flags (benchmark-design note, records kept)

Class-revealing titles: lido L-02 ("Potential Overflow"), dinero M-01
("Sandwiched"), lido M-01 ("Front-Running" in body title), hana L-01
("Whitelist/Blacklist"). Flagged here, not dropped.

## Provenance coverage

- 33/33 candidates cite registered source + live receipt + https link.
- Per-finding code locations where observed (19 file-level, 8 function-level
  only, 6 null).
- External finder attribution preserved: lido M-02 (atharv_181), L-01
  (bloqarl).
- License: no license file observed in repo -> `unknown`, METADATA_ONLY.

## Validation results

- `validate_vbeta.py`: 0 critical failures (33 structure/provenance/
  consistency/reference/count/version/evidence checks incl. 4 new evidence
  checks).
- `tests/test_vbeta.py`: all pass, incl. 7 Shieldify-specific tests.
- PRESENT isolation: sentinels unchanged; Vbeta writes confined to `Vbeta/`.
