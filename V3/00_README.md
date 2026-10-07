# VLUN V3 — New-source research (folder `V3/`)

Research lead output for VLUN v3. Goal: **ranked, verifiable, independently useful
sources of real smart-contract/blockchain security evidence** that materially improve VLUN.

Governing principle (unchanged): `TRUTH > COMPLETENESS > SCALE > METRICS`.
Nothing in this folder invents findings, commits, PoCs, or labels. Anything not
verified from the web is marked `UNKNOWN`. URLs listed here were all observed in
live search/fetch results during this research session — no guessed URLs.

## Scope guardrails (per task)

- All research artefacts live in `V3/` only. Nothing outside `V3/` was read or changed.
- Existing VLUN corpus (CoinFabrik, Hacken, Oak, Dedaub, Softstack, Hashlock,
  Auditware, QuillAudits, HashEx, TechRate, Decentraland, 0xRayaa, Trail of Bits,
  ChainSecurity, Consensys Diligence, Spearbit, MixBytes, OpenZeppelin, Halborn,
  Solidstate) was **not** re-harvested; it is referenced only for dedup.
- GitHub API quota is nearly spent: no `gh` API calls were made. All verification
  used web search + page fetch only.

## Files

| File | Contents |
|---|---|
| `01_ranked_table.md` | Ranked table (spec section 25) + A/B/C/D division (section 26) |
| `02_source_dossiers.md` | Per-source dossiers: URLs, why valuable, evidence, langs, ecosystems, commits, fix, PoC, negatives, licence, priority |
| `03_synthesis.md` | Gap analysis, gap→source mapping, L5/L6, hard negatives, cross-language, fix chains, leakage (section 27) |
| `04_top10.md` | TOP 10 new sources with P0/P1/P2 (section 28) |
| `sources.json` | Machine-readable ingestion list (candidate pointers only — no redistributed third-party content) |
| `99_method_log.md` | Searches run, verification signals, rate-limit notes, what was NOT verified |

## Headline result

- **15 sources recommended for immediate ingestion (P0)**, 5 P1, 5 P2/discovery.
- Biggest V3 wins available: (1) competitive-audit fix chains + hard negatives
  (Code4rena / Sherlock / Cantina), (2) Solana + Move depth (Zellic / OtterSec /
  Neodyme), (3) three **new languages/ecosystems** with zero VLUN coverage today:
  **Clarity/Stacks (Cyba)**, **Sway/Fuel (Hexens)**, **Soroban/Stellar-Rust
  (Runtime Verification + Certora Blend)**, plus **Cosmos/IBC (Informal Systems)**
  and **ZK circuits (Veridise: Circom/Halo2/Noir/Leo/o1js)**.
- Best L5/L6 bets: DeFiHackLabs (executable Foundry PoCs now) + Cantina/Code4rena
  (scope commit + mitigation PR + verified fix) + Immunefi disclosures (PoC + patch).
- Licence posture for all new sources: **METADATA_ONLY by default** (link + sha256 +
  extracted facts with attribution). No third-party PDF/code redistribution without
  per-source licence confirmation. See dossiers.

## How to use this in the pipeline (suggested, not implemented)

1. Ingest P0 competitive sources first (they also supply hard negatives).
2. Add one new-ecosystem source at a time (Clarity → Sway → Soroban → Cosmos → ZK),
   each with its own toolchain note (`environment_unavailable` where tooling is absent).
3. Cross-validate every incident-derived record against its primary postmortem
   (SlowMist/BlockSec/REKT are triage only, never ground truth alone).
4. Extend `splits_v2_2`-style pointer splits: no source spans splits; dedup
   (protocol, commit, finding) across auditors and across contest platforms.
