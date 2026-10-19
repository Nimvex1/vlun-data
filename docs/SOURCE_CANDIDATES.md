# Source Candidates

Research deliverable: additional public smart-contract / blockchain vulnerability
sources for the VLUN corpus, beyond what V1/V3/Vbeta/V4 already cover.
All live checks below were executed on 2026-10-16 unless a row says otherwise.

Method: GitHub REST API metadata (`api.github.com/repos/...` — stars, licence,
`pushed_at`, size), raw-file fetches (`raw.githubusercontent.com`), repo
contents API, and web search for sites that block direct fetches. Every
candidate was deduplicated by grepping the repo docs before admission; sources
that turned out to be already tracked are listed under **Already tracked** and
must not be resubmitted.

Excluded by instruction (not re-evaluated): BlockSec (incl.
`blocksecteam/audit-reports`), PoPoC ecosystem, Cyfrin audit-checklist,
Solodit mirror (already harvested).

Legend
- Confidence: `verified-live` = fetched this session; `partially-verified` =
  some checks blocked/incomplete; `unverified` = could not confirm.
- Licence posture: OPEN = permissive; DERIVATIVE_ALLOWED = attribution /
  share-alike; anything unknown or restrictive -> ingest as METADATA_ONLY
  (link + sha256 + attributed facts, no bulk text/code redistribution).
- Tier 1 = first-party publisher; Tier 2 = aggregator / mirror / index.
- Priority: P0 act now / P1 next / P2 later.

---

## 1. zkbugs

- Org: zksecurity (GitHub org).
- Primary URL: https://github.com/zksecurity/zkbugs
- Source type: incident_poc + dataset (ZKP vulnerability corpus with
  reproduction scripts).
- Languages / ecosystems: Circom, Halo2, Cairo, Bellperson, Arkworks, PIL,
  Gnark, Plonky3, Risc0 (ZK circuits, non-EVM).
- Observed volume: 140 vulnerabilities (Circom 70, Halo2 35, Cairo 8,
  Plonky3 8, Bellperson 7, Arkworks 5, PIL 3, Risc0 3, Gnark 1); repo tagline
  "Reproduce ZKP vulnerabilities"; 350 stars; pushed 2026-09-30 (GitHub API,
  checked 2026-10-16).
- Structure / format: per-bug directories with source, writeup, and
  reproduction scripts; git history hash-pinnable.
- Execution depth: L4-L5 — reproduction scripts/instructions per bug.
- Provenance: first-party security firm, curated from contests, audits and
  disclosures; each bug traceable to upstream source.
- Licence: MIT (OPEN).
- Overlap risk: none observed (repo-wide grep found no `zkbugs` in existing
  docs; current corpus is EVM-dominant, this adds ZK coverage).
- Suggested source_id: `zkbugs`
- Tier / priority: Tier 1, P0.
- Ingestion notes: clone repo, parse per-bug metadata, store reproduction
  script refs; effort M (small record count, but 9 frameworks to map).
- Confidence: verified-live.

## 2. SunWeb3Sec/DeFiVulnLabs

- Org: SunWeb3Sec (also authors of the already-covered DeFiHackLabs —
  different repo, disjoint content).
- Primary URL: https://github.com/SunWeb3Sec/DeFiVulnLabs
- Source type: exploit-lab / taxonomy (dated Foundry test cases per vuln
  class).
- Languages / ecosystems: Solidity (EVM).
- Observed volume: repo states "Currently supports 48 types of
  vulnerabilities"; 1,979 stars; active test suite under Foundry (checked
  2026-10-16).
- Structure / format: one Solidity test file per vulnerability class with
  inline explanation; runnable with `forge test`.
- Execution depth: L4 — executable reproductions.
- Provenance: community-maintained; per-file upstream references vary
  (inline links to incidents/blog posts).
- Licence: none declared (API `license: null`) -> METADATA_ONLY posture.
- Overlap risk: none observed against docs; distinct from DeFiHackLabs even
  though same org.
- Suggested source_id: `defivulnlabs`
- Tier / priority: Tier 1, P1.
- Ingestion notes: clone; run tests to verify reproducibility; store as
  technique-taxonomy negatives/positives; licence negotiation advisable
  before redistributing code. Effort M.
- Confidence: verified-live.

## 3. MixBytes audits_public

- Org: MixBytes (audit firm).
- Primary URL: https://github.com/mixbytes/audits_public
- Source type: professional_audit (PDF corpus).
- Languages / ecosystems: Solidity (EVM), some Rust/Substrate.
- Observed volume: 528 stars; 1,103 commits; ~348 MB of report PDFs; latest
  reports observed dated 2026-10-07 (checked 2026-10-16).
- Structure / format: one directory per engagement, PDF inside.
- Execution depth: L1-L2 (report prose; occasional code snippets).
- Provenance: first-party.
- Licence: none declared (`license: null`) -> METADATA_ONLY.
- Overlap risk: none observed.
- Suggested source_id: `mixbytes-audits`
- Tier / priority: Tier 1, P1.
- Ingestion notes: clone (large); PDF-text extraction pipeline; index by
  client + date. Effort L.
- Confidence: verified-live.

## 4. Hashlock-Auditing/hashlock-audits

- Org: Hashlock (audit firm).
- Primary URL: https://github.com/Hashlock-Auditing/hashlock-audits
- Source type: professional_audit.
- Languages / ecosystems: Solidity (EVM).
- Observed volume: `audits.json` (25 KB) indexes clients with availability
  tiers, e.g. `{"client":"Rocket Pool","slug":"rocket-pool","tier":"TIER 1
  (public PDF)","hasBugBounty":false}` and `{"client":"1inch","tier":"TIER 2
  (NDA)"}`; repo created 2026-05-19, pushed 2026-10-12, ~604 MB (API,
  checked 2026-10-16).
- Structure / format: machine-readable `audits.json` + `clients/<slug>/`
  PDFs + `docs/`; a structured index is rare among audit repos.
- Execution depth: L1-L2 reports; TIER 1 entries are public PDFs, TIER 2
  flagged NDA (skip).
- Provenance: first-party, self-classified availability.
- Licence: MIT (OPEN) for repo; PDF content may carry per-report terms —
  still treat long excerpts as attributed quotes.
- Overlap risk: none observed.
- Suggested source_id: `hashlock-audits`
- Tier / priority: Tier 1, P1.
- Ingestion notes: clone; parse `audits.json`; ingest only TIER 1 PDFs;
  NDA tier is a built-in negative filter. Effort M.
- Confidence: verified-live.

## 5. DAppSCAN

- Org: InPlusLab (Chinese University of Hong Kong / academic).
- Primary URL: https://github.com/InPlusLab/DAppSCAN
- Source type: dataset (paper companion, TSE 2024) + audit-report corpus.
- Languages / ecosystems: Solidity (EVM; Ethereum + Polygon sources).
- Observed volume: 39,904 Solidity files, 1,618 SWC-labeled weaknesses
  across 682 projects; `audit_report/` PDFs included (repo + paper docs,
  checked 2026-10-16).
- Structure / format: dataset directories + scripts; JSON metadata.
- Execution depth: L1-L3 (static dataset with labels; no PoCs).
- Provenance: academic (peer-reviewed artifact).
- Licence: verify per file (default METADATA_ONLY until confirmed).
- Overlap risk: none observed.
- Suggested source_id: `dappscan`
- Tier / priority: Tier 1, P1.
- Ingestion notes: clone; map SWC labels to the repo taxonomy; useful for
  scale and for injected-label negatives. Effort M.
- Confidence: verified-live.

## 6. Consensys Diligence audit archive

- Org: ConsenSys Diligence (audit firm; deepest historical EVM archive).
- Primary URL: https://consensys.io/diligence/audits/ (site; returns 403 to
  direct fetch) + per-project repos under https://github.com/ConsenSysDiligence
  (e.g. `0x-review` verified via API).
- Source type: professional_audit.
- Languages / ecosystems: Solidity (EVM); historical depth back to 2016.
- Observed volume: search-indexed report pages expose per-report JSON/CSV
  downloads and per-finding sections (e.g. 0x review repo); exact report
  count not established this session.
- Structure / format: HTML report pages with per-finding anchors + JSON/CSV
  exports = close to ideal structure.
- Execution depth: L1-L3 (findings, some PoC snippets).
- Provenance: first-party, per-report hash/version metadata.
- Licence: unknown -> METADATA_ONLY.
- Overlap risk: none observed (repo grep found no consensys/diligence refs).
- Suggested source_id: `consensys-diligence`
- Tier / priority: Tier 1, P1.
- Ingestion notes: site 403s scripted fetches — scrape with a browser-like
  client or via ConsenSysDiligence git repos where available; prefer JSON/CSV
  over PDF/HTML text. Effort M.
- Confidence: partially-verified (site fetch blocked; GitHub org + search
  evidence confirm existence/structure).

## 7. Cyfrin/audits (report index)

- Org: Cyfrin (audit firm; competitive arm CodeHawks is already covered —
  this is the private-client/report index).
- Primary URL: https://github.com/Cyfrin/audits (old URL
  `Cyfrin/cyfrin-audit-reports` now 404s — migrated; search index still
  shows the old repo at 351 stars).
- Source type: professional_audit index (structured metadata; per-report
  severity counts).
- Languages / ecosystems: Solidity/EVM plus Solana/Rust, C++/ZK (Aztec),
  Substrate (from per-auditor tech tags).
- Observed volume: README (fetched 2026-10-16) indexes ~13 categories with
  totals: Stablecoin 22 reports, NFT 18, Liquid Staking 18, DAO 15,
  ERC4337 12, UniswapV4 Hooks 11, Token Sale 10, Gaming 9, Staking 8,
  Prediction Market 8, ZK/Crypto 8, Tranche 6, Off-Chain 5; auditor totals
  incl. Dacian 47, Immeas 45, Kage 41, Hans 31, Farouk 27. Private clients
  are listed as `REDACTED`. Repo created 2026-10-16T15:37Z, 1 star, no
  licence detected (API).
- Structure / format: Markdown tables with C/H/M/L/I/G counts per report —
  ready-made severity ground-truth metadata.
- Execution depth: L1-L2 reports (PDFs referenced from the index).
- Provenance: first-party; fresh migration (created same day as check).
- Licence: none declared -> METADATA_ONLY.
- Overlap risk: CodeHawks contests already covered; this index is distinct
  (private-client reports).
- Suggested source_id: `cyfrin-audits`
- Tier / priority: Tier 1, P1.
- Ingestion notes: parse README tables into severity-count records now;
  recheck in 1-2 weeks whether PDFs were backfilled into the repo. Effort S.
- Confidence: verified-live (new URL; README content fetched).

## 8. ChainSecurity/audits

- Org: ChainSecurity (audit firm).
- Primary URL: https://github.com/ChainSecurity/audits
- Source type: professional_audit (PDF corpus).
- Languages / ecosystems: Solidity (EVM).
- Observed volume: ~20 reports, 2017-2019; 22 commits (checked 2026-10-16).
- Structure / format: PDFs.
- Execution depth: L1-L2.
- Provenance: first-party, historical.
- Licence: none declared -> METADATA_ONLY.
- Overlap risk: none observed.
- Suggested source_id: `chainsecurity-audits`
- Tier / priority: Tier 1, P2 (stale but provenance-clean).
- Ingestion notes: small clone; PDF decode. Effort L (volume small).
- Confidence: verified-live.

## 9. Dedaub/audits

- Org: Dedaub (audit firm).
- Primary URL: https://github.com/Dedaub/audits
- Source type: professional_audit (PDF corpus).
- Languages / ecosystems: Solidity (EVM).
- Observed volume: 54 stars; 33 commits; last push 2023-11-27 (checked
  2026-10-16).
- Structure / format: per-project directories with PDFs.
- Execution depth: L1-L2.
- Provenance: first-party.
- Licence: CC-BY-SA-4.0 (DERIVATIVE_ALLOWED — attribution + share-alike
  obligations; cleanest licence among the auditor repos).
- Overlap risk: none observed.
- Suggested source_id: `dedaub-audits`
- Tier / priority: Tier 1, P2 (stale).
- Ingestion notes: clone (~11 MB); PDF decode; respect SA terms when
  redistributing text. Effort S/M.
- Confidence: verified-live.

## 10. statemindio/public-audits

- Org: Statemind (audit firm).
- Primary URL: https://github.com/statemindio/public-audits
- Source type: professional_audit (PDF corpus).
- Languages / ecosystems: Solidity (EVM) — Lido, Symbiotic, Curve, Yearn
  engagements observed.
- Observed volume: 27 stars; 46 commits; reports dated 2023-04 through
  2026-07 (checked 2026-10-16).
- Structure / format: PDFs per project.
- Execution depth: L1-L2.
- Provenance: first-party; high-signal client list.
- Licence: none declared -> METADATA_ONLY.
- Overlap risk: none observed.
- Suggested source_id: `statemind-audits`
- Tier / priority: Tier 1, P2.
- Ingestion notes: small clone; PDF decode. Effort S/M.
- Confidence: verified-live.

## 11. GuardianAudits/Audits

- Org: Guardian Audits (audit firm).
- Primary URL: https://github.com/GuardianAudits/Audits
- Source type: professional_audit (PDF corpus).
- Languages / ecosystems: Solidity (EVM) + some non-EVM (verify per repo).
- Observed volume: ~269 commits; many per-project directories (API +
  search, checked 2026-10-16); exact report count not established.
- Structure / format: PDFs per project.
- Execution depth: L1-L2.
- Provenance: first-party.
- Licence: none declared -> METADATA_ONLY.
- Overlap risk: none observed.
- Suggested source_id: `guardian-audits`
- Tier / priority: Tier 1, P2.
- Ingestion notes: clone; PDF decode. Effort M.
- Confidence: verified-live (repo); volume partially-verified.

## 12. Paradigm CTF series

- Org: Paradigm (repo org `paradigmxyz`).
- Primary URL: https://github.com/paradigmxyz (repos under
  `paradigm-ctf-*`; e.g. `paradigm-ctf-2023`, `paradigm-ctf-2022`,
  `paradigm-ctf-2021`).
- Source type: ctf.
- Languages / ecosystems: Solidity (EVM).
- Observed volume: 2023 repo: 20 challenge directories verified via contents
  API; series spans 2021-2023 (checked 2026-10-16).
- Structure / format: per-challenge dirs with contracts + challenge setup;
  **no solutions in the repo** (README file exists but is not `README.md`).
- Execution depth: L4 potential — challenges are runnable, but ground truth
  requires solving or external writeups.
- Provenance: first-party challenge releases.
- Licence: none declared -> careful redistribution.
- Overlap risk: none observed.
- Suggested source_id: `paradigm-ctf`
- Tier / priority: Tier 1, P2.
- Ingestion notes: clone per year; pair with public writeups
  (blocksec-ctfs index below) to obtain solutions. Effort M.
- Confidence: verified-live.

## 13. spearbit/portfolio

- Org: Spearbit (audit firm / Cantina-adjacent).
- Primary URL: https://github.com/spearbit/portfolio
- Source type: professional_audit corpus + links.
- Languages / ecosystems: Solidity (EVM), Rust/Solana.
- Observed volume: 575 stars; ~17 MB; pushed 2026-10-07 (checked
  2026-10-16).
- Structure / format: per-engagement folders; README now links mostly to
  Cantina (already covered).
- Execution depth: L1-L2 historically; competitions pages linked.
- Provenance: first-party.
- Licence: none declared -> METADATA_ONLY.
- Overlap risk: **high** — primary links point at Cantina, which the corpus
  already covers; unique value is older local PDFs not on Cantina.
- Suggested source_id: `spearbit-portfolio`
- Tier / priority: Tier 1, P2.
- Ingestion notes: clone; ingest only engagements not already reachable via
  Cantina. Effort S (after dedup).
- Confidence: verified-live.

## 14. SC-Bench (system-pclub/SC-Bench)

- Org: Penn State / UCSD authors (repo org `system-pclub`).
- Primary URL: https://github.com/system-pclub/SC-Bench (artifact URL given
  in the paper: "We have released SC-Bench and all our source code at
  https://github.com/system-pclub/SC-Bench", arXiv 2410.06176, ICSE-LLM4Code
  2025).
- Source type: dataset (academic).
- Languages / ecosystems: Solidity (EVM) — ERC-20/721/1155 compliance focus.
- Observed volume: 5,377 real-world contracts; 15,975 ERC violations —
  139 real violations from 30 contracts, 15,836 systematically injected
  (paper abstract, checked 2026-10-16). Repo: `dataset/`, `erc/`, `py/`,
  Dockerfile + pytest; created 2024-07-01, 11 commits (search-observed).
- Structure / format: JSON per contract (injected-error metadata +
  LLM-response files).
- Execution depth: L1-L3 (labels + oracle code sites; no exploit PoCs).
- Provenance: peer-reviewed paper artifact.
- Licence: none observed -> METADATA_ONLY until confirmed.
- Overlap risk: none observed; distinct from ScaBench (already ingested —
  different org, different content).
- Suggested source_id: `scbench`
- Tier / priority: Tier 1, P2.
- Ingestion notes: clone; Docker/pytest to reproduce described pipeline;
  mostly-injected labels are useful for evaluation, not as organic ground
  truth. Effort S/M.
- Confidence: partially-verified (artifact existence + contents from paper
  and search; API not re-fetched).

## 15. rustsec/advisory-db

- Org: RustSec (Rust security working group).
- Primary URL: https://github.com/rustsec/advisory-db
- Source type: advisory_db (CVE/RUSTSEC records).
- Languages / ecosystems: Rust — filter needed for web3 crates
  (solana-program, anchor, tokio-adjacent dependencies, etc.).
- Observed volume: 1,187 stars; pushed 2026-10-16 (checked same day) —
  actively maintained.
- Structure / format: TOML advisories with standard IDs, affected ranges,
  references — ideal structured format.
- Execution depth: L1 (advisories; some link to PoCs).
- Provenance: first-party security DB; CVE cross-references.
- Licence: NOASSERTION (mixed) -> METADATA_ONLY.
- Overlap risk: none observed; only the web3-filtered subset is relevant.
- Suggested source_id: `rustsec-advisory-db`
- Tier / priority: Tier 1, P2.
- Ingestion notes: clone; filter crate names against a web3 list; TOML parse
  is trivial. Effort S.
- Confidence: verified-live.

## 16. OpenZeppelin/damn-vulnerable-defi

- Org: OpenZeppelin.
- Primary URL: https://github.com/OpenZeppelin/damn-vulnerable-defi
- Source type: exploit-lab (educational).
- Languages / ecosystems: Solidity (EVM).
- Observed volume: 755 stars; ~15-19 challenges across versions (checked
  2026-10-16).
- Structure / format: per-challenge Foundry/Hardhat workspaces with test
  harnesses.
- Execution depth: L4-L5 — runnable exploit tests.
- Provenance: first-party (OpenZeppelin).
- Licence: MIT (OPEN, API-verified).
- Overlap risk: none observed.
- Suggested source_id: `damn-vulnerable-defi`
- Tier / priority: Tier 1, P2.
- Ingestion notes: clone; run test suite; small volume, high quality.
  Effort S.
- Confidence: verified-live.

## 17. OpenZeppelin/ethernaut

- Org: OpenZeppelin.
- Primary URL: https://github.com/OpenZeppelin/ethernaut
- Source type: ctf (educational).
- Languages / ecosystems: Solidity (EVM).
- Observed volume: 2,337 stars; pushed 2026-10-15 (checked 2026-10-16); 30+
  levels.
- Structure / format: per-level contracts + tests.
- Execution depth: L4 — testable levels.
- Provenance: first-party.
- Licence: AGPL-3.0 — copyleft; METADATA_ONLY posture for redistribution.
- Overlap risk: none observed.
- Suggested source_id: `ethernaut`
- Tier / priority: Tier 1, P2.
- Ingestion notes: clone; small volume; licence restricts code reuse.
  Effort S.
- Confidence: verified-live.

## 18. blockthreat/blocksec-ctfs

- Org: blockthreat (journalist-maintained).
- Primary URL: https://github.com/blockthreat/blocksec-ctfs
- Source type: index (curated CTF list + writeups).
- Languages / ecosystems: mixed (mostly EVM; index-level).
- Observed volume: 167 commits; CC0-1.0 licence; curated list of blockchain
  CTFs incl. Paradigm, Damn Vulnerable DeFi, Ethernaut-like sources
  (checked 2026-10-16).
- Structure / format: Markdown lists with links.
- Execution depth: n/a (pointer file).
- Provenance: community curation.
- Licence: CC0-1.0 (OPEN).
- Overlap risk: none (index only).
- Suggested source_id: `blocksec-ctfs`
- Tier / priority: Tier 2, P2.
- Ingestion notes: clone; use as a discovery index, always attribute the
  original challenge repos. Effort S.
- Confidence: verified-live.

---

## Top 5 to act on

1. **zkbugs** (`zksecurity/zkbugs`, MIT) — 140 executable ZK PoCs across 9
   frameworks; adds non-EVM depth the corpus lacks; smallest effort to
   highest new coverage. Start a pilot.
2. **Hashlock** (`Hashlock-Auditing/hashlock-audits`, MIT) — machine-readable
   `audits.json` with built-in TIER 1/TIER 2 availability filter; active
   (pushed 2026-10-12). Parse the index first, PDFs second.
3. **DeFiVulnLabs** (`SunWeb3Sec/DeFiVulnLabs`) — 48 vulnerability classes as
   runnable Foundry tests (L4); licence absent, so ingest via metadata +
   links until terms are negotiated.
4. **MixBytes** (`mixbytes/audits_public`) — largest fresh first-party PDF
   corpus (1,103 commits; reports through 2026-10-07); metadata-only
   posture, PDF-extraction pipeline needed.
5. **DAppSCAN** (`InPlusLab/DAppSCAN`) — academic, SWC-labeled scale (39,904
   files / 682 projects) plus audit-report PDFs; strong for evaluation splits.

Runner-ups: Consensys Diligence (JSON/CSV per finding — revisit once the 403
workaround is built) and Cyfrin/audits (parse the fresh index now, recheck
PDF backfill in 1-2 weeks).

## Already tracked — do not resubmit

Sources that live research surfaced but that the repo already covers:

- **Sherlock org** (`sherlock-audit`) — already ranked A16, P0 in
  `V3/02_source_dossiers.md`; two contests cloned
  (`V3/clones/MANIFEST.md`). Extension of the existing C4-style pipeline,
  not a new source.
- **SlowMist Hacked** — already documented (V3 B-source, 2,299 events);
  live count now 2,311 (refresh value only; triage-only, never ground truth
  alone).
- **DeFiLlama hacks** — already among converted sources
  (`reports/cloned_repo_conversion.md`).
- **Quantstamp** — already documented as a V3 B-source.
- **ScaBench** (`scabench-org/scabench`, MIT) — already ingested in Vbeta
  (`Vbeta/reports_vbeta/scabench_ingestion_report.md`; 550 candidates
  harvested, source registered as `scabench`).
- **Hats Finance** — already piloted (`reports/hats_pilot_evaluation.md`;
  L3 run failed, no tests in DAOsis repo).
- **ABDK, Sigma Prime, Ackee, Anza, BlockSec** — already documented V3
  B-sources (do not resubmit as "new").

## Rejected / not recommended

- **AuditBench** — no smart-contract dataset exists under this name; it
  collides with unrelated AI-alignment/auditing benchmarks (arXiv
  2606.10281, 2602.22755). One-line rejection.
- **`Cyfrin/cyfrin-audit-reports` (old URL)** — returns 404 as of
  2026-10-16 (migrated); use `Cyfrin/audits` instead (candidate 7).
- **Cyfrin audit-checklist** — excluded per brief (licence).
- **BlockSec / blocksecteam/audit-reports** — excluded per brief.
- **Solodit** — mirror already harvested; no new value.
