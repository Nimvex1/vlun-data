# V3 research synthesis (spec section 27)

## A. What VLUN currently lacks (from repo context + known gaps)

1. **Languages/ecosystems:** 0 Clarity, 0 Sway, 0 Soroban/Stellar-Rust, 0 Cosmos
   (CosmWasm/Go/IBC), ~0 ZK-circuit (Circom/Halo2/Noir/Leo/o1js) records. Move (15)
   and Cairo (8) exist but cannot reach L3+ locally (no sui/aptos/scarb/snforge).
2. **Patch verification at scale:** v1 G patch family has only 38 rows; v2.2 fix
   evidence is strong per-report but thin across auditors (single-auditor view).
3. **Hard negatives:** 458 v1 negatives exist, but competitive `invalid/duplicate/
   downgraded/QA` negatives with full `claim → counterargument → code → decision`
   chains are under-represented.
4. **Incident linkage:** incident + code + exploit + patch (G6) chains are rare;
   audit-before-exploit (missed/regression) cases are the most valuable and scarcest.
5. **Independent confirmation:** most records single-auditor; multi-auditor same-target
   sets (SPL Token, Granite, Lido, Aave V4, RISC Zero) are unexploited.
6. **Temporal coverage:** commit A → audit → finding → commit B → deploy → incident →
   fix → re-audit chains exist in sources but are not yet first-class VLUN views.
7. **Toolchain honesty:** Move/Cairo L3+ impossible locally; ZK-circuit execution needs
   Picus/circuit tooling (absent); Cosmos needs Go/Rust + chain harness.

## B. Gap → source → data-type → improvement map

| VLUN gap | Source | Data type | Expected improvement |
|---|---|---|---|
| No Clarity records | Cyba (Granite series) | Clarity audit findings + re-reviews, 5-auditor confirmation | New language family; post-condition/principal-auth classes |
| No Sway records | Hexens Fuel series | Sway + Solidity bridge findings, fix commits | New language; bridge-accounting classes |
| No Soroban/Stellar records | Runtime Verification (OctoLend/Trustless/TokenOps) + Certora Blend | Soroban-Rust findings + Kontrol/Certora specs | New ecosystem; keep `reported_claim` + `environment_unavailable` until runner exists |
| No Cosmos/IBC records | Informal Systems + Cosmos IBC docs + Dragonberry retro | CosmWasm/Go findings, IBC spec audits, protocol_bug chain | New ecosystem + `protocol_bug` origin (currently rare) |
| ~0 ZK-circuit records | Veridise ZK archive (+ ABDK circuits, Hexens avacloud) | Under-constrained/nullifier/witness findings + Picus counterexamples | Entirely new vuln taxonomy (family-R material) |
| Thin Move depth (15) | Zellic Move (Cetus/Suilend/Echelon/Initia/DeepBook) + OtterSec Move traces | Move findings with fix commits | 2–3x Move findings; resource/capability classes |
| Thin Cairo depth (8) | Nethermind Cairo (TokenTable/ZKX/zkLend) + Veridise MakerDAO-Cairo | Cairo findings with commit pairs | 2–4x Cairo findings; bridge/AMM classes |
| Vyper depth (51, no FV) | Certora (Vyper Prover support — verify per report) | Vyper FV rules + findings | Verification-view for Vyper family |
| Patch verification scale | Cantina + Code4rena mitigation PRs + Pashov fix hashes + Immunefi patches | `audit → finding → fix-commit → verified` triples | 10x patch-verifiable rows (G-family growth) |
| Hard negatives scale | Code4rena + Sherlock (duplicates/invalid/QA) | Judged rejected findings with rationale | 2–5x hard negatives with decision chains |
| Incident+exploit (L5 now) | DeFiHackLabs + BlockSec tx/PoC + Immunefi PoCs | Executable Foundry PoCs, attack txs, root causes | L5 rows without waiting for new toolchains |
| Bounty→patch chains | Immunefi disclosures + fix reviews | Reported + acked + evidenced + fixed | Severity-reconciliation (L-family) + patch rows |
| Independent confirmation | SPL Token / Granite / Lido / Aave V4 / RISC Zero multi-auditor sets | Same-target findings from 2–6 auditors | Confirmation-view benchmark (new family material) |
| Formal-spec reasoning | Certora + Runtime Verification (Kontrol) + Informal (TLA+) | Invariants, rules, specs | Reasoning supervision beyond labels |

## C. Most likely L5/L6 producers

- **L5 now (execute locally, EVM/Foundry present):** DeFiHackLabs (forge PoCs),
  Immunefi PoC tests (`RepaymentFeeTheft.t.sol` pattern), Cantina/C4 PoCs,
  Pashov PoC-bearing findings. No new toolchain needed.
- **L5 after small harness work:** Solana Rust (Zellic/OtterSec/Neodyme) via existing
  temp-venv/Anchor-adjacent approach used for Vyper; Clarity via Clarinet (to be proven —
  until then `reported_claim` + `environment_unavailable`); Sway via `forc` (absent —
  same posture); Soroban via Stellar toolchain (absent — same posture).
- **L6 (vuln + fixed, correct reason both sides):** Cantina verified-fix rows, C4
  mitigation-review rows, Pashov review→fix-review pairs, Nethermind/Neodyme/Zellic
  commit-pair rows, Immunefi patch rows, Certora zero-finding verified-clean reports
  as the fixed-side anchor.
- **G6 narrative chains (audit+incident+fix):** Penpie (Zokyo + AstraSec + SlowMist +
  Veridise analyses), Euler `donateToReserves` (audit-fix-becomes-vuln + BlockSec
  debugger trace), Curve Vyper `compiler_bug` (LlamaRisk postmortem + Vyper 0.3.1
  boundary), Telcoin proxy/wallet slot-0 (BlockSec remediation audit), KiloEx
  TrustedForwarder (SlowMist + permission-audit follow-up).

## D. Best hard-negative sources

1. Code4rena (duplicates, downgraded H/M→QA, QA reports, sponsor disputes).
2. Sherlock (accepted/invalid folder accounting — reconciling contests only).
3. Cantina (acknowledged + informational + test-gap appendix).
4. Immunefi-adjacent aggregators for *patterns* only (never as negatives alone).
5. Pashov/Certora acknowledged/low findings (weak negatives — use with code context).

## E. Best cross-language reasoning sources

1. Cantina Sunrise (EVM + Solana same-protocol findings).
2. Zellic (Solana + Move + EVM in one methodology).
3. Hexens (EVM + Sway + Solana + circuits).
4. OtterSec (Solana + EVM + Stellar + Move traces).
5. Nethermind (Solidity + Cairo joint reports, e.g. ZKX Starkway).
6. Garden C4 contest (EVM + Solana + Sui + Starknet single scope — verify at ingestion).

## F. Best audit → fix → re-audit chains

1. Cantina (per-finding fix commit + "Fix verified").
2. Code4rena (mitigation PR per finding + mitigation review).
3. Pashov (review hash → fix-review hash).
4. Neodyme/Nethermind/Zellic (audited commit → last-reviewed/final commit + deployed-hash checks).
5. Immunefi (disclosure → patch diff → bounty-paid acknowledgement).
6. Granite via Cyba (Core → Safety → Enhancements → Liquidations = 4-link chain on one protocol).

## G. Leakage risks (must-engineer-against)

1. **Cross-platform same-finding:** Lido CSM / Aave V4 / large launches appear on C4 +
   Sherlock + Cantina + private audits — dedup by (protocol, scope-commit, finding),
   split by source-repository (extend `splits_v2_2` pointer discipline).
2. **Multi-auditor same-target:** SPL Token 2022 (6+ auditors), Granite (5), RISC Zero
   (Veridise + Hexens) — keep both for confirmation views but NEVER span splits.
3. **Shared libraries:** circomlib/Circom-bigint, OpenZeppelin `MinimalForwarderUpgradeable`
   (KiloEx pattern), Anchor boilerplate — library-level dedup note per record.
4. **Incident PoC reuse:** DeFiHackLabs PoCs reference BlockSec analyses and vice versa —
   record `mirror_of`/derived-from, one canonical record.
5. **Benchmark answer leakage (by design, documented):** family-K language-prefix pattern
   must be re-examined before adding Clarity/Sway/Soroban families (prefix scheme extends
   cleanly, but re-document).
6. **Temporal leakage:** fix commits post-date scope commits — splits must respect
   commit-time ordering where temporal tasks are built.
