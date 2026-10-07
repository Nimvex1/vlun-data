# V3 ranked sources (spec section 25)

Scores use spec section 10 weights (auth 15 / depth 15 / commits 15 / repro 15 /
fix 10 / specificity 10 / diversity 10 / confirmation 5 / negatives 5).
Quantity never dominates: a small deep archive outranks a huge shallow one.
`UNKNOWN` means not verified, never a guess.

| Rank | Source | Type | Quality | Ground-truth potential | Languages (observed) | Ecosystems (observed) | Exact commits | Fix / re-audit | PoCs | Negative value | V3 recommendation |
|---:|---|---|---:|---|---|---|---|---|---|---|---|
| 1 | Code4rena (`code-423n4` org) | COMPETITIVE_AUDIT | 91 Exceptional | G5 | Solidity | EVM (+ occasional Solana/Sui/Starknet, e.g. Garden contest) | YES — scope commit + mitigation PRs | YES — mitigation review flow | OFTEN — PoC required by judges | HIGHEST — duplicates + invalid visible, judged | **A — ADD (P0)** |
| 2 | Cantina (Spearbit) | COMPETITIVE_AUDIT, PROFESSIONAL_AUDIT | 90 Exceptional | G5 | Solidity, Rust (Solana) | EVM, Solana | YES — e.g. Sky `c4e4f8ca`→`b044009d`, `efc7a928`→`03fa6e86`; Infrared fix commits `5c7b970c`, `784d3470` | YES — "Fixed / Fix verified" per finding | OFTEN — PoC in report (e.g. USDai inflation attack) | HIGH — QA/low + acknowledged | **A — ADD (P0)** |
| 3 | Zellic publications | PROFESSIONAL_AUDIT | 92 Exceptional | G5 | Rust (Solana), Move (Sui/Aptos), Solidity | Solana, Sui, Aptos, EVM, TON (LayerZero USDT TON observed) | YES — audited + fix commits (e.g. Initia `ae04bf3f` observed) | YES — acknowledged/fixed status | SOMETIMES | MEDIUM — mostly valid findings | **A — ADD (P0)** |
| 4 | OtterSec | PROFESSIONAL_AUDIT | 90 Exceptional | G5 | Rust (Solana/Anchor), Solidity, Rust (Soroban/Stellar observed), Move (see dossier) | Solana, EVM, Stellar, Move-ecosystems (verify per report) | YES — e.g. Upshift `592be1c` | YES — resolved status per finding | SOMETIMES | MEDIUM | **A — ADD (P0)** |
| 5 | Veridise ZK archive | PROFESSIONAL_AUDIT, FORMAL_VERIFICATION | 88 Excellent | G4 (some G5) | Circom, Halo2, Noir, Leo (Aleo), o1js/TS (Mina), Cairo, Rust, Solidity, Go, C++ | ZK (multiple proving stacks), Mina, Aleo, Starknet-adjacent, EVM | YES — e.g. o1js `02f2ffb6`, risc0 `a6159d9`/`35c65de`, zkemail.nr `2f81196` | YES — Fixed/Acknowledged tables | SOMETIMES (circuit counterexamples) | LOW-MEDIUM | **A — ADD (P0)** |
| 6 | Pashov Audit Group | PROFESSIONAL_AUDIT | 86 Excellent | G5 (G4 where no PoC) | Solidity | EVM (DeFi-heavy: AMM, lending, stablecoins, vaults) | YES — review hash + fix-review hash (e.g. RWf(x) `f6e865d`→`80c514e`) | YES — fixes review | SOMETIMES | LOW-MEDIUM | **A — ADD (P0)** |
| 7 | Neodyme | PROFESSIONAL_AUDIT | 88 Excellent | G5 | Rust (Solana/Anchor) | Solana (core + top protocols) | YES — e.g. stabble `12c18ed`→`fc465ad`, Squads `ca85338`→`dcac867` + deployed program-hash check | YES — fixes verified (e.g. `74fafb1`) | SOMETIMES | LOW (few invalid shown) but HIGH confirmation value | **A — ADD (P0)** |
| 8 | Nethermind Security | PROFESSIONAL_AUDIT | 85 Excellent | G5 | Solidity, Cairo, Rust, Circom, TypeScript (per practice page) | EVM, Starknet | YES — e.g. TokenTable `30808fd`→`e3ec394`, ZKX `f933f59`→`5564a90` | YES — fix-review branch re-checked | SOMETIMES | LOW-MEDIUM | **A — ADD (P0)** |
| 9 | Certora | PROFESSIONAL_AUDIT, FORMAL_VERIFICATION | 85 Excellent | G5 | Solidity, Vyper, Rust (Solana), Soroban-Rust (Blend observed) | EVM, Solana, Stellar/Soroban | YES — ranges (e.g. Balancer `8df7df5`→`e4455af`) | YES — all-issues-addressed pattern; prover rules shipped | RARE (specs, not exploits) | LOW | **A — ADD (P0)** |
| 10 | Hexens | PROFESSIONAL_AUDIT | 86 Excellent | G5 (EVM) / G4 (Sway, pending toolchain) | Solidity, Sway, Rust (Solana), circuits (AvaCloud observed) | EVM, Fuel, Solana, ZK-adjacent | YES — per-report commits + fix commits (Fuel bridge observed) | YES — fixed/acknowledged + validated | SOMETIMES | MEDIUM | **A — ADD (P0)** |
| 11 | DeFiHackLabs | INCIDENT_DATABASE, SECURITY_RESEARCH | 78 Strong | G5 (exploit repro); G6 only with linked audit+fix | Solidity (Foundry) | EVM (multi-chain: mainnet, BSC, Arbitrum, Base, etc.) | PARTIAL — attack tx + addresses, not audited/fix commits | RARE | YES — 500+ `forge test` PoCs | LOW (no judged invalids) | **A — ADD (P0)** |
| 12 | Immunefi disclosures (`reports.immunefi.com` + bug-fix reviews) | BUG_BOUNTY_DISCLOSURE | 82 Strong-Excellent | G5 | Solidity (+ Solana e.g. Raydium tick case via aggregator write-up) | EVM, Solana (verify per report) | PARTIAL — target branch/file+line, rarely pinned commit | YES — patch described (e.g. Yield `poolCached_`), bounty paid = acknowledgement signal (not truth) | OFTEN | LOW (only accepted published) | **A — ADD (P0)** |
| 13 | Informal Systems audits | PROFESSIONAL_AUDIT, FORMAL_VERIFICATION | 81 Excellent | G4 | Rust (CosmWasm), Go (SDK/IBC), TLA+ | Cosmos (Osmosis, Neutron, Celestia, Hub, Stride, Anoma/Namada) | PARTIAL — some pinned (IBC v2 `79218a5` via Cosmos docs); many link issues/PRs | PARTIAL — follow-up audits common | RARE | LOW | **A — ADD (P0)** |
| 14 | Cyba Blockchain Security | PROFESSIONAL_AUDIT | 81 Excellent | G4/G5 (Clarity G4 pending Clarinet check) | Clarity, Solidity | Stacks/Bitcoin-L2, EVM | PARTIAL — repos named (Granite etc.); pin per report at ingestion | YES — re-reviews observed (Granite Core → Safety → Enhancements → Liquidations) | UNKNOWN (verify) | LOW, but HIGH multi-auditor confirmation (Granite: Strata/Halipot/ABA/Clarity Alliance/Cyba) | **A — ADD (P0)** |
| 15 | Runtime Verification public reports | PROFESSIONAL_AUDIT, FORMAL_VERIFICATION | 80 Excellent | G4/G5 | Solidity, Rust (Soroban) | EVM, Stellar/Soroban | PARTIAL — verify per report (Kontrol/KaaS artefacts) | YES — remediations verified (OctoLend observed) | RARE | LOW | **A — ADD (P0)** |
| 16 | Sherlock (`sherlock-audit` org) | COMPETITIVE_AUDIT | 87 Excellent | G5 | Solidity | EVM | YES — scope commit per contest; judging issues + `NNN-H/M` + `invalid/` folders | PARTIAL — fix links where sponsor posts them | OFTEN | HIGHEST — accepted/invalid folder accounting (use only reconciling contests) | **A — ADD (P0, after C4 pipeline)** |
| 17 | ABDK Consulting | PROFESSIONAL_AUDIT | 75 Strong | G4/G5 | Solidity, circuits (Circom-style: Tornado, zkLink, ZkSwap) | EVM, ZK | PARTIAL — verify per report | PARTIAL | RARE | LOW | **B→A (P1)** |
| 18 | BlockSec Phalcon incidents | INCIDENT_DATABASE, OFFICIAL_POSTMORTEM (some), SECURITY_RESEARCH | 76 Strong | G4 (G6 with linked audit+fix) | Solidity | EVM | PARTIAL — tx + code, rarely commits | PARTIAL — remediation audits (e.g. Telcoin) | OFTEN (via DeFiHackLabs linkage + Fork debugger) | LOW | **B→A (P1)** |
| 19 | Sigma Prime | PROFESSIONAL_AUDIT | 72 Strong | G4 | Rust, Go, Solidity | Ethereum infra (Reth, Lighthouse), L2, EVM | YES — e.g. Omni `21652a7`, Polygon bridge `1403e2b` | PARTIAL | RARE | LOW | **B (P1)** |
| 20 | Ackee Blockchain | PROFESSIONAL_AUDIT | 77 Strong | G5 | Solidity (Solana possible — verify) | EVM | YES — verify per report (Lido engagements observed) | YES — pattern | UNKNOWN | LOW-MEDIUM | **B (P1)** |
| 21 | SlowMist Hacked | INCIDENT_DATABASE | 61 Useful secondary | G1 (G2 candidate; G4 only via primary postmortem) | Multi | Multi-chain | NO | NO (tracks recovery stats, not fixes) | NO (links out) | NONE | **B discovery only (P2)** |
| 22 | Quantstamp (decentralised reports) | PROFESSIONAL_AUDIT | 65 Useful secondary | G4 where full report found | Solidity | EVM | PARTIAL — scattered in client repos (e.g. MakerDAO `c8a1344`→`8aae83` reaudit observed) | PARTIAL | RARE | LOW | **B discovery only (P2)** |
| 23 | Anza (`anza-xyz/security-audits`, ex-Solana-Labs) aggregator | OTHER (aggregator) | 60 Useful secondary | G0/G1 pointer | Rust (Solana) | Solana core | MIRROR — points to primaries | MIRROR | NO | NONE | **B pointer only (P2)** — record `mirror_of` auditor originals |
| 24 | SmartBugs curated | RESEARCH_DATASET, STATIC_ANALYSIS_DATASET | 46 Discovery only | G2 max | Solidity (old versions) | EVM | NO (synthetic curation) | NO | NO | NONE (labels are the claim) | **C research only (P2)** |
| 25 | REKT news / De.Fi Rekt DB (JS-heavy, thin fetch) | INCIDENT_DATABASE | UNKNOWN (unverifiable in session) | G0/G1 max | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | NONE observed | **C/D — do NOT ingest until verifiable fetch; prefer SlowMist/BlockSec (D for now)** |

## Division (spec section 26)

- **A — ADD TO VLUN V3 (15 + Sherlock = 16):** Code4rena, Cantina, Zellic, OtterSec,
  Veridise-ZK, Pashov, Neodyme, Nethermind, Certora, Hexens, DeFiHackLabs, Immunefi,
  Informal, Cyba, Runtime Verification (+ Sherlock immediately after the C4 pipeline
  is built — same code path).
- **B — SECONDARY / DISCOVERY (5):** ABDK (promote to A after 5-report pilot),
  BlockSec (promote per incident-linkage pilot), Sigma Prime, Ackee,
  SlowMist + Quantstamp + Anza-aggregator as **discovery pointers only** (P2).
- **C — RESEARCH ONLY (1):** SmartBugs curated (taxonomy + benchmark-design
  reference; never ground truth).
- **D — REJECT (for now, with reason):** REKT/De.Fi thin-fetch endpoints (unverifiable
  this session — recheck with a renderer before any use); any scraped-PDF mirror
  without auditor attribution (`mirror_of` instead); token-only/basic-ERC20 audit
  mills (none recommended — all A/B sources above show protocol-level depth);
  anonymous audit claims (none included).
