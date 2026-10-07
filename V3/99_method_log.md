# Method log — what was searched, verified, and NOT verified

## Search directions run (spec section 23: broad → auditor → GitHub → ecosystem → verification → cross-ref)

1. Broad auditor harvest: `blockchain security firm public audit reports GitHub 2024 2025`
   → Ackee, Cyba, X3, CyStack, MixBytes-traces, Lido/Aave aggregators.
2. Auditor-specific: Zellic, Quantstamp, OtterSec, Nethermind, Ackee, Pashov,
   Runtime Verification, Veridise-ZK, Hexens, ABDK/Sigma Prime, Cyba/Clarity, Informal/Cosmos.
3. GitHub-ecosystem: `code-423n4` findings repos (Reserve/nibiru/phi/renzo/Garden),
   `sherlock-audit` judging repos + reconciliation methodology, `anza-xyz/security-audits`
   Solana core matrix, `informalsystems/audits`, `pashov/audits`, Certora SecurityReports.
4. Incident/bounty: DeFiHackLabs (+ Bybit PoC file), SlowMist Hacked + annual reports +
   Penpie/KiloEx analyses, BlockSec Phalcon library + Telcoin postmortem, Immunefi
   `reports.immunefi.com` (Term-Structure/Yeet/Alchemix) + fix reviews + write-up aggregators.
5. Vuln/fix-chain/regression: Cantina portfolio (HMX/Sunrise/Infrared/Sky/USDai),
   Penpie cross-audit postmortems (Zokyo/AstraSec/SlowMist/Veridise), Curve Vyper
   compiler-bug postmortem, Euler `donateToReserves` audit-fix analysis, Exactly debt-manager case.
6. ZK/academic: Veridise ZK archive (fetched full table), SmartBugs curated + paper.
7. First-party fetch verification: `osec.io/audits` (ok),
   `veridise.com/audits-archive/zero-knowledge-security/` (ok, full table),
   `hexens.io/audit-reports` (ok), `reports.zellic.io/` (transport error — GitHub + zellic.io used instead).

## Rate-limit notes
- Search backend returned `429` on ~8 of ~30 queries; affected queries were retried
  once with narrower terms or deferred (no data invented for failed queries).
- No GitHub API calls made (quota guardrail). All GitHub evidence is from web-visible
  repo pages/search snippets, re-verifiable at ingestion time.

## Verification standard applied
- Every URL in dossiers was observed live (search result or fetch). No guessed URLs.
- Counts from auditor marketing pages (e.g. "600+ audits", "1M+ LoC", "2299 events")
  are treated as `reported_claim`, never ground truth.
- Commit SHAs quoted (Zellic/Neodyme/Nethermind/Cantina/Pashov/Certora/o1js/risc0/…) were
  observed in report text or repo history snippets; re-pin at ingestion (mutable branches
  must go through VLUN's existing `resolve_citations` discipline).
- OtterSec Move support and Ackee Solana support are flagged VERIFY-PER-REPORT (traces
  seen, no full Move/Solana report read this session).
- REKT/De.Fi endpoints fetched as JS shells only → marked unverifiable, rejected for now.

## NOT verified (future work — do not assert until checked)
- Cyfrin private audits, Secureum, yAcademy, CodeHawks results depth, Hats Finance,
  Sec3/Kudelski/Least-Authority/ZKSecurity/Qedit/Asymmetric Solana reports,
  MoveBit/Aptos-framework audits, TON Tact/FunC beyond Hexens-TON row, Cardano
  Plutus/Aiken, ICP Motoko, Stellar beyond RV/Certora-Blend, Substrate/Polkadot
  Frontier beyond Immunefi write-ups, Noirgunning beyond Veridise rows.
- Per-report licences for every A-source (default METADATA_ONLY stands).
- DeFiHackLabs repo LICENSE file; SmartBugs-curated LICENSE; per-contest C4/Sherlock licences.
- Clarinet/`forc`/Soroban/Stellar execution harnesses for L3+ on new languages.
