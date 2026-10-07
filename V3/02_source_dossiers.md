# V3 source dossiers (spec sections 7–15, 20–22)

Conventions: `UNKNOWN` = not verified this session. Licence classes from spec
section 22 (`OPEN / DERIVATIVE_ALLOWED / METADATA_ONLY / RESTRICTED / UNKNOWN`).
Default ingestion posture for ALL auditor PDFs: **METADATA_ONLY** (link + sha256 +
extracted attributed facts) until per-report licence is confirmed — consistent with
VLUN's existing `work/`-gitignored / citations-kept posture.

---

## A1. Code4rena — `code-423n4` findings repos

- Official: `https://docs.code4rena.com/competitions` (judging/mitigation process observed).
- GitHub: `https://github.com/code-423n4` — per-contest findings repos, e.g.
  `https://github.com/code-423n4/2024-07-reserve-findings`,
  `https://github.com/code-423n4/2024-09-reserve-mitigation-findings`,
  `https://github.com/code-423n4/2024-10-coded-estate-findings`,
  `https://github.com/code-423n4/2024-11-nibiru-findings`,
  `https://github.com/code-423n4/2024-08-phi-findings`,
  `https://github.com/code-423n4/2024-04-renzo-findings`,
  `https://github.com/code-423n4/2025-11-garden` (multi-chain scope observed).
- Why: judged findings + duplicate labels + sponsor responses + **mitigation PRs
  linked per finding** = `audit → finding → fix` chains at scale; QA/low reports =
  best hard negatives; scope commits pinned per contest.
- Evidence: wardens submit without seeing each other; judge dedups, labels
  `3 (High)` / `2 (Medium)` / `duplicate`; sponsor must respond to H/M and may link
  one mitigation PR per finding (observed in Reserve/nibiru/phi/renzo repos).
- Languages: Solidity (primary). Garden contest scope spans EVM + Solana + Sui +
  Starknet in one audit — verify per contest.
- Ecosystems: EVM DeFi mostly; Garden = cross-ecosystem (verify).
- Depth: HIGH variance per warden, but judged set is curated; final audit reports
  published on code4rena site.
- Commits: YES (scope commit per contest + mitigation PR SHAs).
- Fix/re-audit: YES — mitigation-review flow is the differentiator (G5).
- PoC: OFTEN (judges reward coded PoCs; Alchemix-style PoC tests observed on
  adjacent Immunefi comps — require per-finding check here).
- Negatives: HIGHEST (duplicates, `sponsor disputed`, downgraded H/M→QA, QA reports).
- Licence: UNKNOWN per repo — check each findings repo LICENSE before copying text;
  default METADATA_ONLY.
- Priority: **P0**. Ingest judged H/M as positives, duplicates/downgraded/QA as
  hard negatives with `claim → counterargument → code → decision` preserved.
- Ground truth: G5 max. Type: COMPETITIVE_AUDIT.

## A2. Cantina (Spearbit) portfolio reviews

- Official: `https://cantina.xyz/portfolio` (findings/fixed counts + fix-commit links observed).
- Examples observed: `https://cantina.xyz/portfolio/5977ae92-9528-4871-9968-4ef0508ce9b9`
  (HMXv2, 22 findings / 12 fixed), `https://cantina.xyz/portfolio/3ac4f595-baf3-4c8d-8a62-fb6fac4ed4cc`
  (Sunrise SettlementSale Solana: forced-lockup finding, fix `sunrisedotdev/svm-spearbit#1`),
  Infrared vaults (fix commits `5c7b970c`, `784d3470`, `c8b44ba7`, `efd0ccff` observed),
  Sky reviews `https://cdn.cantina.xyz/reports/cantina_sky_oft_evm_sep2025.pdf`
  (`c4e4f8ca`→`b044009d`) and `cantina_sky_lz_governance_evm_sep2025.pdf`
  (`efc7a928`→`03fa6e86`).
- Why: per-finding **"Fixed in <commit> / Fix verified"** with exact SHAs; EVM+Solana
  coverage of the *same* protocol (Sunrise) = cross-language reasoning; inflation-attack
  PoC (USDai `StakedUSDai`, fix `4e214097`) = L5 material.
- Languages: Solidity, Rust/Solana (Borsh, Ed25519 precompile, CPI guards observed).
- Ecosystems: EVM, Solana, cross-chain (LayerZero OFT, governance relays).
- Commits: YES. Fix: YES (verified-fix pattern). PoC: OFTEN. Negatives: HIGH
  (informational/acknowledged + test-coverage appendix suggests untestable claims).
- Licence: UNKNOWN (report PDFs © Cantina/client) — METADATA_ONLY.
- Priority: **P0**. Ground truth G5. Types: COMPETITIVE_AUDIT, PROFESSIONAL_AUDIT.

## A3. Zellic publications

- Official: `https://www.zellic.io/our-work` (client list incl. Solana Foundation,
  LayerZero, Jump, Injective observed); reports hub `https://reports.zellic.io/`
  (search-observed; direct fetch failed this session — re-verify at ingestion).
- GitHub (primary machine source): `https://github.com/Zellic/publications`
  (README table observed: Ondo Solana, LayerZero Solana Endpoint, Anza BPF/Token2022,
  Cetus/Echelon/Magma/Suilend/Initia Move, SPL Token 2022; batch commit `c7c0dcb` observed).
- Sample: `https://reports.zellic.io/publications/spl-token-2022` (7 findings,
  2 critical, Solana Sealevel threat model: account ser/de, mint accounting, extensions).
- Why: only P0 source with **simultaneous Solana + Move + EVM depth**; Move bytecode
  verifier work (Mysten/Sui) + Solana core (SPL Token 2022, Anza BPF) = fills VLUN's
  weakest axes; fix commits referenced (Initia `ae04bf3f` observed).
- Languages: Rust/Solana, Move (Sui/Aptos), Solidity.
- Commits: YES. Fix: YES. PoC: SOMETIMES. Negatives: MEDIUM. Licence: UNKNOWN — METADATA_ONLY.
- Priority: **P0**. G5. Type: PROFESSIONAL_AUDIT.

## A4. OtterSec

- Official (fetched + verified): `https://osec.io/audits` (per-report C/H/M/L/I counts;
  examples: Metadao Solana `1C/1H/3M/1L/5I`, Sui Sentinel `1C/3H/2M/4L/3I`,
  Solana Keychain, Ember Vaults EVM, Mercury/Rango Stellar).
- GitHub org: `https://github.com/otter-sec` (verified; maintains
  `otter-sec/anchor`, Solana CTF framework, `solana-verified-programs-api`).
- Sample: Upshift Solana ERC4626 (`https://docs.upshift.finance/audits/ottersec-2025-09-solana-vault.pdf`,
  scope `defiborg/solana-erc4626 @ 592be1c`, Aug 2025).
- Why: Anchor maintainers = highest Solana signal; Solana + EVM + Stellar + Move
  traces in one archive; Solana-Foundation `rewards` repo pins OtterSec report +
  audited-through commit + delta file (commit `13773bf` observed) = exemplary provenance.
- Languages: Rust/Solana, Solidity, Soroban-Rust/Stellar, Move (Magna/Movement traces —
  **verify per report at ingestion**; do not assert until seen).
- Commits: YES. Fix: YES. PoC: SOMETIMES. Negatives: MEDIUM. Licence: UNKNOWN — METADATA_ONLY.
- Priority: **P0**. G5. Type: PROFESSIONAL_AUDIT.

## A5. Veridise ZK archive

- Official (fetched + verified): `https://veridise.com/audits-archive/zero-knowledge-security/`
  (60+ rows; langs/tags per row; clients: Risc Zero, Succinct, Linea, Mina, Semaphore, Demox/Aleo).
- Samples (search-observed PDFs): Arianee Full-Privacy (`.../VAR_Arianee_Circuits-Final.pdf`,
  4 issues incl. critical CreditNoteProof theft, scope `Arianee/arianee-sdk`
  `packages/privacy-circuits/src/circom`); o1js (`.../VAR_o1js_240318_o1js_V3.pdf`,
  63 issues incl. under-constrained circuits, scope commits `02f2ffb6`/`e7ded4b6`);
  RISC Zero zkVM (`.../VAR-Risc0-241028-Round2-V4.pdf`, 41 issues, Zirgen/Picus,
  commits `f7fae1d`/`a6159d9`/`35c65de`); Keccak precompile (`.../VAR-RISC0-Keccak-250129-V2.pdf`,
  commits `65645b0`, `b74b267`); Manta (`.../manta-circuits-2023-09-01/`, 182 fuzz-hours).
- Why: **only source for VLUN's ZK gap** (under-constrained circuits, nullifiers,
  witness/circuit bugs) across Circom/Halo2/Plonky/Noir/Leo/o1js/Zirgen/gnark/Cairo;
  tool-assisted (Picus/Vanguard) + manual; severity+status tables.
- Commits: YES. Fix: YES (Fixed/Acknowledged/Partial). PoC: SOMETIMES (counterexamples).
  Negatives: LOW-MEDIUM. Licence: UNKNOWN — METADATA_ONLY.
- Priority: **P0** (entirely new vuln classes). G4 (G5 where executable check exists).
  Types: PROFESSIONAL_AUDIT, FORMAL_VERIFICATION.

## A6. Pashov Audit Group

- GitHub (verified, 1310 stars): `https://github.com/pashov/audits` (team table:
  Uniswap/Sushi/Reya/Gains/Bunni + Aave/Hyperlend/Blueberry + Resolv/Ethena/Hyperstable…;
  solo archive back to Q4-2022).
- Samples: `team/md/RWf(x)-security-review_2025-08-20.md` (review `f6e865d` →
  fix-review `80c514e`, H-01/M-01 with NatSpec-level cause), `team/md/Aave-security-review.md`,
  `team/md/Arcadia-security-review-October.md`, `team/md/Resolv-security-review-October.md`.
- Why: 300+ audits in **parseable markdown** with review+fix hashes, file scope,
  severity, recommendation — cheapest high-quality ingestion in this entire list;
  DeFi-heavy (accounting/oracle/liquidation classes VLUN wants).
- Languages: Solidity. Commits: YES. Fix: YES. PoC: SOMETIMES. Negatives: LOW-MEDIUM.
  Licence: UNKNOWN — reports are markdown in public repo; still confirm per-repo
  LICENSE before bulk text ingestion (METADATA_ONLY default).
- Priority: **P0**. G5 (G4 without PoC). Type: PROFESSIONAL_AUDIT.

## A7. Neodyme

- Official (search-verified): `https://neodyme.io/reports/` (SHA256 + last-commit columns),
  `https://neodyme.io/blockchain/` (Solana since 2020, 80+ core bugs, $10B TVL claims —
  treat counts as *reported_claim* until independently confirmed).
- Samples: Stabble AMM (`https://neodyme.io/reports/Stabble.pdf`: `amm-v1 12c18ed→fc465ad`,
  `amm-sdk be385d2→f15d379a`, Token2022/hook issues); Marinade Bonds
  (`.../Marinade-Validator-Bonds.pdf`: `afbdad4→7e6d35e`, H-01 locked-stake claim);
  Squads v4 (`.../SQD03.pdf`: `ca85338→dcac867` + deployed program-hash match,
  fix `74fafb1`); Drift (`.../Drift.pdf`: 1 critical + 2 medium in complex perp stack).
- Why: deepest Solana-only bench; **audited→fixed commit pairs + deployed-binary
  verification** is the exact provenance VLUN needs for L5; core-program multi-auditor
  overlap (Anza aggregator) enables confirmation.
- Languages: Rust/Solana (Move mentioned on services page — UNKNOWN until a Move
  report is seen). Commits: YES. Fix: YES. PoC: SOMETIMES. Negatives: LOW.
  Licence: UNKNOWN — METADATA_ONLY.
- Priority: **P0**. G5. Type: PROFESSIONAL_AUDIT.

## A8. Nethermind Security

- GitHub (verified): `https://github.com/NethermindEth/PublicAuditReports`.
- Practice (verified): `https://www.nethermind.io/smart-contract-audit-reports`
  (Solidity/Rust/Cairo/Circom/TS; 1M+ LoC, 1700+ findings — *reported_claim*),
  `https://www.nethermind.io/smart-contract-audits`.
- Samples: TokenTable Cairo NM-0447 (PR #3, Cairo 2.9.2, `30808fd→e3ec394`, 1051 LoC,
  2 medium) and NM-0163 (`f7253f2→95172d6`, 1599 LoC); ZKX Starkway NM-0120
  (Solidity+Cairo, `f933f59→5564a90` fix branch, 26 points); zkLend Cairo 0/1 via
  `NM0058`/`NM0097` (see `zklend.gitbook.io/.../audit-and-formal-specification`).
- Why: **best Cairo+Solidity joint archive** (directly upgrades VLUN's 8 Cairo records);
  Starknet-native (bridge, Starkway, zkLend) + EVM L1/L2.
- Commits: YES. Fix: YES. PoC: SOMETIMES. Negatives: LOW-MEDIUM. Licence: UNKNOWN — METADATA_ONLY.
- Priority: **P0**. G5. Type: PROFESSIONAL_AUDIT.

## A9. Certora

- GitHub (verified): `https://github.com/Certora/SecurityReports` ("Solidity, Vyper,
  Rust, Move, Soroban supported" — tool claim; verify Move per report).
- Hub (verified): `https://www.certora.com/reports` (Royco Dawn, Saturn/M0, Lido V3,
  Re Core 13-fixed, Kamino Vault+Lending, Safe v1.5.0, Silo Core/Router/Vault,
  Aave Risk-Steward/GHO/Vault, UniswapV4-core, LayerZero Endpoint V2, Blend V1 Soroban,
  Boring Bridge Solana, Jito Restaking…), `https://www.certora.com/audits`.
- Samples: Balancer V3 (`8df7df5→e4455af`, FV rules shipped); GhoStewardV2
  (`aave/gho-core` audit, 0 bugs — valuable **verified-clean** point); Lido V3
  spec+verification set.
- Why: **formal specs + prover rules as artefacts** (strongest non-execution evidence;
  complements L5); Vyper FV (VLUN has 51 Vyper records); Soroban Blend = Stellar path.
- Commits: YES. Fix: YES. PoC: RARE. Negatives: LOW (but zero-finding verified reports
  are clean-signal). Licence: UNKNOWN — METADATA_ONLY.
- Priority: **P0**. G5. Types: PROFESSIONAL_AUDIT, FORMAL_VERIFICATION.

## A10. Hexens

- GitHub (verified, 56 stars): `https://github.com/Hexens/Smart-Contract-Review-Public-Reports`.
- Hub (fetched + verified): `https://hexens.io/audit-reports` (1inch Solana/Fusion,
  Lido V2, EigenLayer, Polygon zkEVM, RISC Zero zkVM, Fuel x10 incl. Sway standards +
  bridge updates, TRAIN Solana+Fuel, Everclear/Holdfast Solana, ZKsync, TON Mar-2023 row).
- Sample: Fuel bridge (`Fuel-Bridge-apr24(Public).pdf`: Solidity + Sway + predicates,
  1H/6M/8L-I, fix commits cited; page `https://hexens.io/audit-reports/fuel-token-bridge-apr-2024`).
- Why: **Sway/Fuel (new language) + Solana + ZK-EVM + TON traces** in one first-party
  archive; RISC Zero overlap with Veridise = independent confirmation pair.
- Commits: YES. Fix: YES. PoC: SOMETIMES. Negatives: MEDIUM. Licence: UNKNOWN — METADATA_ONLY.
- Priority: **P0**. G5 EVM / G4 Sway (toolchain check). Type: PROFESSIONAL_AUDIT.

## A11. DeFiHackLabs (SunWeb3Sec)

- GitHub (verified, ~7K stars, 500+ incidents):
  `https://github.com/SunWeb3Sec/DeFiHackLabs` (+ `past/2025/README.md`,
  `CONTRIBUTING.md` entry schema: network/file/timestamp/loss/attacker/attack-contract/
  vulnerable-contract/tx/postmortem/twitter/researcher).
- Sample: `src/test/2025-02/Bybit_exp.sol @ 1cd8127` (KeyInfo: $1.5B, attacker/attack/
  vulnerable addresses, attack tx `0x46deef…`, `testExploit` + `testFakeExploit`).
- Why: **immediate L5 executables** (`forge test` per PoC); per-incident loss/chain/
  address/tx schema maps cleanly to VLUN experiment views; links SlowMist/De.Fi/Rekt/
  Cryptosec/BlockSec dashboards.
- Commits: PARTIAL (tx/addresses, not repo commits). Fix: RARE. PoC: YES. Negatives: LOW.
  Licence: UNKNOWN — check repo LICENSE; PoCs call on-chain code (no redistribution
  issue for VLUN's own PoC files, but confirm).
- Priority: **P0** (L5 engine). G5 (G6 when audit+fix linked). Types: INCIDENT_DATABASE, SECURITY_RESEARCH.

## A12. Immunefi disclosures

- Official reports (verified samples): `https://reports.immunefi.com/term-structure-institutional_iop/46903-sc-critical-malicious-borrower-can-take-theft-of-other-borrower-collateral`
  (target `term-structure/tsi-contract/.../Settlement.sol`, expiry/repay theft, PoC steps);
  `.../yeet/42527-...` (StakeV2 insolvency, `bank-run` mechanics + mitigation code);
  `.../alchemix-v3/58772-...` (`AlchemistV3.sol#L894-L909` fee-overpay + PoC test
  `src/test/poc/RepaymentFeeTheft.t.sol`).
- Bug-fix reviews (verified): `https://immunefi.com/blog/bug-fix-reviews/yield-protocol-logic-error/`
  (Paludo0x, $95k, `burn()` → `poolCached_` fix, ~$950k at risk — *reported_claim*).
- Aggregators (third-party, discovery only): `https://github.com/sayan011/Immunefi-bug-bounty-writeups-list`
  (Wormhole $10M, Aurora $6M, Optimism $2M…), `https://github.com/tpiliposian/Immunefi-bugfixes`
  (Raydium tick `$505k`, Silo/Certora-verified fix, DFX rounding, Enzyme forwarder, Frontier truncation).
- Why: `reported issue + acknowledgement (bounty) + technical evidence + fix` quintuple
  (spec section 3) in one record; whitehat + researcher + tx trails.
- Caution: bounty-paid ≠ true (spec: treat payout as acknowledgement signal only).
- Commits: PARTIAL (branch/file+line; pin SHA at ingestion). Fix: YES. PoC: OFTEN.
  Negatives: LOW (only accepted published). Licence: RESTRICTED/METADATA_ONLY presumed — never copy full reports.
- Priority: **P0**. G5. Type: BUG_BOUNTY_DISCLOSURE.

## A13. Informal Systems audits (Cosmos/IBC)

- GitHub (verified): `https://github.com/informalsystems/audits` (Zenrock/Anoma/Neutron/
  Osmosis/Celestia/Stride/DYDX/IBC-Go rows; e.g. `Osmosis/2022-09-30 ... Token Factory.md`,
  `IBC-GO` TLA+ audit).
- Protocol docs (verified): `https://docs.cosmos.network/ibc/latest/security-audits`
  (IBC v2 audit, commit `79218a5`, 74 pp; WASM client Halborn; ICS-27).
- Retrospective (verified): Cosmos Dragonberry/Elderflower forum thread (ICS-23 IAVL
  forgery + Authz bypass, Oct 2022, coordinated patch) = `protocol_bug` origin + incident chain.
- Why: **only Cosmos/IBC/CosmWasm source in this round** (Rust+Go+TLA+); IBC packet/
  channel/connection classes have zero VLUN coverage; multi-client overlap enables confirmation.
- Commits: PARTIAL. Fix: PARTIAL (follow-up audits). PoC: RARE. Negatives: LOW.
  Licence: UNKNOWN — METADATA_ONLY.
- Priority: **P0** (new ecosystem). G4. Types: PROFESSIONAL_AUDIT, FORMAL_VERIFICATION.

## A14. Cyba Blockchain Security (Stacks Clarity)

- GitHub (verified): `https://github.com/cybasecurity/audits` (founder Alin Barbatei/ABA;
  Granite Clarity rows Jun-2026/May-2026/Aug-2024/Jun-2024 + EVM rows Liquify/iLayer/Inferno).
- Site (verified): `https://cybasecurity.io/audits` (per-audit finding counts; e.g. Granite
  Safety `3C/4H/3M/2L/12I`, Core `2C/4H/11M/15L/28I`; avg 24.7/audit — *reported_claim*).
- Protocol cross-ref (verified): `https://docs.granite.world/protocol-information/audits-and-bug-bounty`
  (Strata + Halipot + ABA + Clarity Alliance + Cyba on ONE protocol = rare 5-way confirmation set).
- Why: **Clarity is a new language for VLUN** (absent from Solidity/Vyper/Rust/Move/Cairo);
  Bitcoin-L2 (sBTC) trust model = new vuln classes (post-conditions, principal auth);
  repeated Granite engagements = fix-chain depth.
- Commits: PARTIAL (pin per report). Fix: YES (re-review pattern). PoC: UNKNOWN.
  Negatives: LOW. Licence: UNKNOWN — METADATA_ONLY.
- Priority: **P0**. G4/G5 (Clarity G4 until Clarinet execution is proven). Type: PROFESSIONAL_AUDIT.

## A15. Runtime Verification public reports (EVM + Soroban)

- Hub (search-verified): `https://runtimeverification.com/work`,
  `https://runtimeverification.com/smartcontract`; reports: `.../public-report/levery`
  (UniswapV4 AMM + Kontrol FV, Jul–Aug 2025), `.../public-report/octolend` (Stellar
  Collateral Vault + Lending Market, Rust/Soroban, Jan–Feb 2026, remediations verified),
  `.../public-report/trustless-work`, `.../public-report/equitx`, `.../public-report/tokenops`
  (Soroban vesting), `.../public-report/audit-1` (Lido Dual Governance FV + KaaS).
- Why: **Soroban/Stellar Rust (new ecosystem) + Kontrol symbolic-execution specs**;
  invariant documentation per report = reasoning supervision, not just labels.
- Commits: PARTIAL (verify per report). Fix: YES. PoC: RARE. Negatives: LOW.
  Licence: UNKNOWN — METADATA_ONLY.
- Priority: **P0**. G4/G5. Types: PROFESSIONAL_AUDIT, FORMAL_VERIFICATION.

## A16. Sherlock judging repos (P0 pipeline extension)

- Org (verified): `https://github.com/sherlock-audit` (460 repos; e.g.
  `2023-01-optimism-judging`, `2023-02-gmx-judging`, `2024-08-sentiment-v2` with scope
  `protocol-v2 @ 04bf155…`).
- Judging semantics (verified via `holistis/bug-bounty-intelligence-mcp/METHODOLOGY.md`):
  per-contest `NNN-H/M/` + `invalid/` folders = authoritative accepted/rejected accounting;
  only 10/105 contests reconciled exactly in that crawl — **adopt the reconciliation rule**
  (`accepted + invalid == total issues`) before using a contest for negatives.
- Samples: `2024-06-symmetrical-update-2-judging` (H-1 precision, H-2 stuck bridge,
  M-1/M-2/M-3 with fix PR refs), `2025-05-lend-audit-contest-judging` (stale cross-chain
  collateral, liquidation math — cross-chain classes).
- Why: same hard-negative machinery as C4 with different judge pool (diversity);
  L perk: `sherlock.xyz` process docs verify scope-freeze + lead-senior review.
- Commits: YES. Fix: PARTIAL. PoC: OFTEN. Negatives: HIGHEST. Licence: UNKNOWN — per-repo check.
- Priority: **P0 (build on the C4 pipeline)**. G5. Type: COMPETITIVE_AUDIT.

## B-sources (secondary / discovery)

- **ABDK (`https://github.com/abdk-consulting/audits`, 118 stars):** 0x/1inch/Aave/GHO +
  Tornado (`TornadoCash_anonymity_mining…`, `Tornado_circuit_audit.pdf`,
  `Tornado_cryptographic_review.pdf`, `Tornado_solidity_audit.pdf`) + zkLink/ZkSwap/Zeropool.
  Crypto+circuit depth back to 2017. P1, promote after 5-report pilot. G4/G5.
- **BlockSec Phalcon (`https://blocksec.com/security-incident`, `https://blocksec.com/blog/...`):**
  >$100K curated incidents with vuln-type filter + attack-tx + DeFiHackLabs PoC linkage +
  Fork debugger; Telcoin postmortem verified (proxy/wallet slot-0 re-init, 4,958 attacks,
  6 accounts). P1 as incident-linkage layer. G4 (G6 with audit+fix).
- **Sigma Prime (`https://github.com/sigp/public-audits`, `https://sigmaprime.io/`):**
  Omni `21652a7`, Polygon zkEVM bridge `1403e2b`, LinkPool `ce76565→721beb7` reaudit;
  Reth/Lighthouse/Mantle infra. P1 for protocol/infra diversity. G4.
- **Ackee (`https://github.com/Ackee-Blockchain/public-audit-reports`, yearly dirs +
  `.pdf.sig`):** Lido Stonks/CSM/Triggerable engagements observed. P1 EVM depth
  (Solana: verify). G5.
- **SlowMist Hacked (`https://hacked.slowmist.io/`, 2299 events; 2024/2025 annual reports;
  Penpie/KiloEx analyses verified):** triage/discovery ONLY (P2). G1 (G2 candidate).
  Never ground truth alone.
- **Quantstamp (decentralised):** hub `https://quantstamp.com/audits` + cert portal
  `certificate.quantstamp.com` + client repos (`Rari-Capital/audit`, `eq-lab/marginly`,
  `NiftyApes/…`, MakerDAO Liquidations 2.0 `c8a1344→8aae83` reaudit). P2 discovery
  harvest (per-client). G4 where complete.
- **Anza aggregator (`https://github.com/anza-xyz/security-audits`):** Solana core
  programs (Durable Nonce, Versioned TX/LUT, SPL Token 2022, Compression, Governance)
  with Halborn/OtterSec/Neodyme/Zellic/TrailOfBits/NCC/Certora/LeastAuthority/
  ZKSecurity/Code4rena/Qedit/Asymmetric rows. P2 pointer file; always `mirror_of`
  the auditor original.

## C — research only

- **SmartBugs curated (`https://github.com/smartbugs/smartbugs-curated`,
  `https://github.com/smartbugs/smartbugs`, ASE-2020 paper):** 143 contracts / 208
  DASP tags; 47.5k wild set; tool-eval lineage. Use for taxonomy/benchmark-design
  ONLY. G2 max. Never ground truth (synthetic curation, stale compilers, no fixes).

## D — reject (for now, with reasons)

- REKT/De.Fi thin endpoints: fetch returned JS shells only — **unverifiable this
  session**; recheck with renderer, else keep rejected in favour of SlowMist/BlockSec.
- Any unattributed scraped-PDF mirror: record `mirror_of`, never a new source.
- Token-only/ERC20-mill/anon-audit claims: none met the depth bar; none included.
- Secureum/yAcademy/Cyfrin-private-audits: mentioned in passing but **no verified
  primary URL this session — excluded rather than asserted** (future-work list in
  `99_method_log.md`).

## Deduplication notes (spec sections 20–21)

- Same PDF in two places = ONE source (`mirror_of`): Hexens Lido V2 also under
  `lidofinance/audits`; client-embedded Quantstamp PDFs are the auditor's report, not
  the client's; sayan011/tpiliposian aggregate `reports.immunefi.com` (mirror).
- Same protocol across auditors = INDEPENDENCE (keep both, link them): SPL Token 2022
  (Zellic/ToB/NCC/OtterSec/Halborn/Certora/…); Granite (5 auditors); Lido/Aave V4
  (6+ auditors + C4/Sherlock/Cantina); RISC Zero (Veridise + Hexens); Penpie (Zokyo
  pre-registration + AstraSec registration-only + SlowMist/Veridise postmortems =
  `AUDIT_MISSED_EXPLOIT` case study, section 16).
- Same finding across contest platforms = dedup by (protocol, scope-commit, finding):
  expect C4/Sherlock/Cantina/CodeHawks overlap on large launches (Lido CSM, Aave V4).
