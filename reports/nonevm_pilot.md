# Non-EVM execution pilot (spec item 9)

Generated 2026-10-18T19:06:53Z from the artefacts under `experiments_nonevm/`; every count below is recomputed, not typed in.

Platforms: CosmWasm, Solana Anchor, Aptos/Sui Move, Cairo/Scarb. Isolated local scratch environments only - no live-chain transactions, no real funds, no faucet claims, no deployments.

## Headline

* candidates by platform: cosmwasm 4, solana_anchor 3, aptos_move 3, sui_move 12, cairo_scarb 8
* total runs: **76** across **27** unique records; executed runs: **49** (2 records executed at all)
* outcomes: blocked 23, claim_reproduced 11, compile_failed 4, executed_without_impact 38
* ladder reached: L1 23, L2 4, L4 38, L5 11
* artefact integrity: all runs self-consistent

## Per platform

| platform | candidates | runs | executed | outcomes | blockers |
|---|---|---|---|---|---|
| cosmwasm | 4 | 43 | 40 | blocked 3, claim_reproduced 8, executed_without_impact 32 | build_time_exceeds_pilot_budget: gas mispricing is observed through cosmwasm-vm's metered instantiate, which needs the full cosmwasm-vm/Wasmer build graph x1; build_time_exceeds_pilot_budget: the claim is about the Wasmer Singlepass compiler embedded in wasmvm; it needs a cgo wasmvm build (Wasmer plus a Go host) before any assertion can run x1; revision_unresolved: the Levana post-mortem names no commit, contract version or deployment, so no pin can be resolved x1 |
| solana_anchor | 3 | 3 | 0 | blocked 3 | toolchain_missing: solana-anchor (anchor-cli and solana-cli are both absent; `anchor test` needs the BPF build and a local solana-test-validator) x3 |
| aptos_move | 3 | 3 | 0 | blocked 3 | toolchain_missing: aptos-cli x1; toolchain_missing: aptos-cli; and the component named by the record is the Aptos Move VM written in Rust, whose proof is a cargo test inside aptos-core (a workspace whose build exceeds this pilot's per-run budget) x1; toolchain_missing: aptos-cli; the fix commit is in move-language/move's Rust bytecode verifier, so the assertion is a cargo test, not `aptos move test` x1 |
| sui_move | 12 | 17 | 9 | blocked 8, claim_reproduced 3, executed_without_impact 6 | build_time_exceeds_budget: the vulnerable CFG construction lives in move-language/move's bytecode verifier (Rust); the era-matching commits are pinned but the workspace build exceeds the per-run budget x1; dependency_resolution_uncached_sui_framework_rev: same audited repository and same uncached framework pin as POOL-01 x1; dependency_resolution_uncached_sui_framework_rev: the Volo package pins an OtterSec-era Sui framework rev absent from the local cache x1; dependency_resolution_uncached_sui_framework_rev: the audited Navi package pins a Sui framework revision that is not in the local git dependency cache, so resolving it means a full MystenLabs/sui clone x1; native_runner_not_applicable: a crafted compressed script must be sent to a running Sui node; that needs a built sui-node binary plus a localnet, which exceeds this pilot's per-run budget x1; native_runner_not_applicable: the crash is reached through the JSON-RPC deserializer of a running node, not through `sui move test` x1; native_runner_not_applicable_and_build_time_exceeds_budget: the fix is in MystenLabs/sui crates/sui-adapter (Rust full node); a scoped `cargo test` needs the whole Sui workspace build x1; revision_unresolved: the report's Received Commit line is a 39-hex value with no leading 0x and is not resolvable, and the framework pin is not cached x1 |
| cairo_scarb | 8 | 10 | 0 | blocked 6, compile_failed 4 | build_time_exceeds_budget: the claim is about the Rust Cairo VM (starkware-libs/cairo-vm) and its AIR/prover divergence; a scoped cargo test needs the cairo-vm workspace build plus a prover run x1; compile_failed: scarb scarb 2.20.1 (dd18779a1 2026-08-21) no longer accepts the plain #[test] attribute in a cairo-test target (the runner is deprecated in favour of snforge, and snforge needs universal-sierra-compiler, which is absent). First diagnostic: error[E2200]: Plugin diagnostic: Unsupported attribute. x1; native_runner_not_applicable: the affected component is NethermindEth/juno, a Go full node, not a Scarb package; reproducing the Sierra decompression loop needs a Go build of juno x1; revision_unresolved: same CairoLib scope commit, same missing remote x1; revision_unresolved: the audit names CairoLib commits 99b1c0e3/d2d4dd7c but no public repository is identified in the source, so the pin cannot be resolved to a cloneable remote x1; revision_unresolved: the post-mortem names no contract version, commit or deployment x1; toolchain_version_incompatible: the scarb in work/tools (scarb 2.20.1 (dd18779a1 2026-08-21)) cannot build v0.15.0, which declares cairo-version 2.7.0; 0 compiler diagnostics, no test binary built. First diagnostic: Error: `scarb metadata` exited with error x1; toolchain_version_incompatible: the scarb in work/tools (scarb 2.20.1 (dd18779a1 2026-08-21)) cannot build v0.15.1, which declares cairo-version 2.7.0; 0 compiler diagnostics, no test binary built. First diagnostic: Error: `scarb metadata` exited with error x1; toolchain_version_incompatible: the scarb in work/tools (scarb 2.20.1 (dd18779a1 2026-08-21)) cannot build v0.6.0, which declares cairo-version 2.7.0; 0 compiler diagnostics, no test binary built. First diagnostic: Error: `scarb metadata` exited with error x1; toolchain_version_incompatible: v0.2.0 predates the Scarb workspace layout the 2.20.1 toolchain in work/tools expects, and no era-matching scarb is installed x1 |

## Prerequisite matrix

| tool | platform | install status | observed version | install command |
|---|---|---|---|---|
| `cargo` | cosmwasm | installed | cargo 1.98.0 (797e8a9bc 2026-08-05) | `already installed` |
| `rustc` | cosmwasm | installed | rustc 1.98.0 (88d9e12ae 2026-08-18) | `already installed` |
| `crates.io registry access` | cosmwasm | assumed_available | - | `already installed` |
| `anchor-cli` | solana_anchor | missing | - | `cargo install --git https://github.com/coral-xyz/anchor avm --force --locked && avm install latest && avm use latest` |
| `solana-cli (incl. solana-test-validator)` | solana_anchor | missing | - | `sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)" then add ~/.local/share/solana/install/active_release/bin to PATH` |
| `cargo` | solana_anchor | installed | cargo 1.98.0 (797e8a9bc 2026-08-05) | `already installed` |
| `cryptography tooling note` | solana_anchor | not_used | - | `already installed` |
| `aptos-cli` | aptos_move | missing | - | `curl -fsSL "https://get.aptos.dev/cli" | bash   (Linux/macOS; on Windows the documented path is WSL)` |
| `aptos move test (local Move VM)` | aptos_move | missing | - | `curl -fsSL "https://get.aptos.dev/cli" | bash   (Linux/macOS; on Windows the documented path is WSL)` |
| `sui cli: sui 1.48.2 (era-matching for v1.1.1/v1.1.2)` | sui_move | installed | sui 1.48.2-17a9eb8e1914 | `already installed` |
| `sui cli: sui 1.6.3 (era-matching for v1.1.0)` | sui_move | installed | sui 1.6.3-f4a70c8-dirty | `already installed` |
| `move git dependency cache (~/.move)` | sui_move | installed | - | `created on first `sui move` run that resolves a git dependency` |
| `scarb (Cairo/Starknet)` | cairo_scarb | installed | scarb 2.20.1 (dd18779a1 2026-08-21) / cairo: 2.20.0 (https://crates.io/crates/cairo-lang-compiler/2.20.0) / sierra: 1.9.3 | `already installed` |
| `snforge (starknet-foundry)` | cairo_scarb | installed | snforge 0.44.0 | `already installed` |
| `universal-sierra-compiler (required by snforge)` | cairo_scarb | missing | - | `cargo install universal-sierra-compiler` |
| `era-matching scarb for cairo-version 2.7.0` | cairo_scarb | missing | - | `curl --proto '=https' --tlsv1.2 -sSf https://docs.swmansion.com/scarb/install.sh | sh -s -- -v 2.7.2` |

## Runs

| platform | record | run | status | outcome | ladder | assertion | pin | artefacts |
|---|---|---|---|---|---|---|---|---|
| aptos_move | `move:amnis-peg-1-fee-evasion` | `blocked-amnis-peg-1-fee-evasion` | blocked | blocked | L1 | `-` | `08239f04ca1362` | `experiments_nonevm/move__amnis-peg-1-fee-evasion/blocked-amnis-peg-1-fee-evasion` |
| aptos_move | `move:move-vm-value-depth` | `blocked-move-vm-value-depth` | blocked | blocked | L1 | `-` | `47a0391c612407` | `experiments_nonevm/move__move-vm-value-depth/blocked-move-vm-value-depth` |
| aptos_move | `move:zellic-3.2-control-flow-graph-aptos` | `blocked-zellic-3.2-control-flow-graph-aptos` | blocked | blocked | L1 | `-` | `1fa4ed20daaef2` | `experiments_nonevm/move__zellic-3.2-control-flow-graph-aptos/blocked-zellic-3.2-control-flow-graph-aptos` |
| cairo_scarb | `cairo:CS-HRDTCL-001` | `blocked-CS-HRDTCL-001` | blocked | blocked | L1 | `-` | `CairoLib at au` | `experiments_nonevm/cairo__CS-HRDTCL-001/blocked-CS-HRDTCL-001` |
| cairo_scarb | `cairo:CS-HRDTCL-005` | `blocked-CS-HRDTCL-005` | blocked | blocked | L1 | `-` | `CairoLib at au` | `experiments_nonevm/cairo__CS-HRDTCL-005/blocked-CS-HRDTCL-005` |
| cairo_scarb | `cairo:CVE-2022-31153` | `blocked-CVE-2022-31153` | blocked | blocked | L1 | `-` | `v0.2.0` | `experiments_nonevm/cairo__CVE-2022-31153/blocked-CVE-2022-31153` |
| cairo_scarb | `cairo:CVE-2023-23940` | `scarb-v0.6.0-openzeppelin_account-declared_vulnerable` | compile_failed | compile_failed | L2 | `-` | `34bc9548e28882` | `experiments_nonevm/cairo__CVE-2023-23940/scarb-v0.6.0-openzeppelin_account-declared_vulnerable` |
| cairo_scarb | `cairo:CVE-2024-45304` | `scarb-runtime-control-generated-package` | compile_failed | compile_failed | L2 | `nonevm_cairo_control::scaled_multiplies_by_three` | `08fc90d7993200` | `experiments_nonevm/cairo__CVE-2024-45304/scarb-runtime-control-generated-package` |
| cairo_scarb | `cairo:CVE-2024-45304` | `scarb-v0.15.0-openzeppelin_access-declared_vulnerable` | compile_failed | compile_failed | L2 | `-` | `f57642960f1c8c` | `experiments_nonevm/cairo__CVE-2024-45304/scarb-v0.15.0-openzeppelin_access-declared_vulnerable` |
| cairo_scarb | `cairo:CVE-2024-45304` | `scarb-v0.15.1-openzeppelin_access-declared_patched` | compile_failed | compile_failed | L2 | `-` | `2f8a93d7628587` | `experiments_nonevm/cairo__CVE-2024-45304/scarb-v0.15.1-openzeppelin_access-declared_patched` |
| cairo_scarb | `cairo:CVE-2025-29072` | `blocked-CVE-2025-29072` | blocked | blocked | L1 | `-` | `Nethermind Jun` | `experiments_nonevm/cairo__CVE-2025-29072/blocked-CVE-2025-29072` |
| cairo_scarb | `cairo:cairo-vm-sequencer-prover-inconsistency` | `blocked-cairo-vm-sequencer-prover-inconsistency` | blocked | blocked | L1 | `-` | `the Cairo VM a` | `experiments_nonevm/cairo__cairo-vm-sequencer-prover-inconsistency/blocked-cairo-vm-sequencer-prover-inconsistency` |
| cairo_scarb | `cairo:zklend-2025-02-empty-market-accumulator` | `blocked-zklend-2025-02-empty-market-accumulator` | blocked | blocked | L1 | `-` | `not published ` | `experiments_nonevm/cairo__zklend-2025-02-empty-market-accumulator/blocked-zklend-2025-02-empty-market-accumulator` |
| cosmwasm | `rust:CWA-2024-002` | `cosmwasm-std-1.5.3-dev-int256_neg_min_wraps_silently` | executed | executed_without_impact | L4 | `tests::int256_neg_min_wraps_silently` | `crates.io cosm` | `experiments_nonevm/rust__CWA-2024-002/cosmwasm-std-1.5.3-dev-int256_neg_min_wraps_silently` |
| cosmwasm | `rust:CWA-2024-002` | `cosmwasm-std-1.5.3-dev-pow_in_range_control` | executed | executed_without_impact | L4 | `tests::pow_in_range_control` | `crates.io cosm` | `experiments_nonevm/rust__CWA-2024-002/cosmwasm-std-1.5.3-dev-pow_in_range_control` |
| cosmwasm | `rust:CWA-2024-002` | `cosmwasm-std-1.5.3-dev-uint128_pow_overflow_wraps_silently` | executed | executed_without_impact | L4 | `tests::uint128_pow_overflow_wraps_silently` | `crates.io cosm` | `experiments_nonevm/rust__CWA-2024-002/cosmwasm-std-1.5.3-dev-uint128_pow_overflow_wraps_silently` |
| cosmwasm | `rust:CWA-2024-002` | `cosmwasm-std-1.5.3-dev-uint256_pow_overflow_wraps_silently` | executed | executed_without_impact | L4 | `tests::uint256_pow_overflow_wraps_silently` | `crates.io cosm` | `experiments_nonevm/rust__CWA-2024-002/cosmwasm-std-1.5.3-dev-uint256_pow_overflow_wraps_silently` |
| cosmwasm | `rust:CWA-2024-002` | `cosmwasm-std-1.5.3-dev-uint512_pow_overflow_wraps_silently` | executed | executed_without_impact | L4 | `tests::uint512_pow_overflow_wraps_silently` | `crates.io cosm` | `experiments_nonevm/rust__CWA-2024-002/cosmwasm-std-1.5.3-dev-uint512_pow_overflow_wraps_silently` |
| cosmwasm | `rust:CWA-2024-002` | `cosmwasm-std-1.5.3-release-int256_neg_min_wraps_silently` | executed | claim_reproduced | L5 | `tests::int256_neg_min_wraps_silently` | `crates.io cosm` | `experiments_nonevm/rust__CWA-2024-002/cosmwasm-std-1.5.3-release-int256_neg_min_wraps_silently` |
| cosmwasm | `rust:CWA-2024-002` | `cosmwasm-std-1.5.3-release-pow_in_range_control` | executed | executed_without_impact | L4 | `tests::pow_in_range_control` | `crates.io cosm` | `experiments_nonevm/rust__CWA-2024-002/cosmwasm-std-1.5.3-release-pow_in_range_control` |
| cosmwasm | `rust:CWA-2024-002` | `cosmwasm-std-1.5.3-release-uint128_pow_overflow_wraps_silently` | executed | claim_reproduced | L5 | `tests::uint128_pow_overflow_wraps_silently` | `crates.io cosm` | `experiments_nonevm/rust__CWA-2024-002/cosmwasm-std-1.5.3-release-uint128_pow_overflow_wraps_silently` |
| cosmwasm | `rust:CWA-2024-002` | `cosmwasm-std-1.5.3-release-uint256_pow_overflow_wraps_silently` | executed | claim_reproduced | L5 | `tests::uint256_pow_overflow_wraps_silently` | `crates.io cosm` | `experiments_nonevm/rust__CWA-2024-002/cosmwasm-std-1.5.3-release-uint256_pow_overflow_wraps_silently` |
| cosmwasm | `rust:CWA-2024-002` | `cosmwasm-std-1.5.3-release-uint512_pow_overflow_wraps_silently` | executed | claim_reproduced | L5 | `tests::uint512_pow_overflow_wraps_silently` | `crates.io cosm` | `experiments_nonevm/rust__CWA-2024-002/cosmwasm-std-1.5.3-release-uint512_pow_overflow_wraps_silently` |
| cosmwasm | `rust:CWA-2024-002` | `cosmwasm-std-1.5.4-dev-int256_neg_min_wraps_silently` | executed | executed_without_impact | L4 | `tests::int256_neg_min_wraps_silently` | `crates.io cosm` | `experiments_nonevm/rust__CWA-2024-002/cosmwasm-std-1.5.4-dev-int256_neg_min_wraps_silently` |
| cosmwasm | `rust:CWA-2024-002` | `cosmwasm-std-1.5.4-dev-pow_in_range_control` | executed | executed_without_impact | L4 | `tests::pow_in_range_control` | `crates.io cosm` | `experiments_nonevm/rust__CWA-2024-002/cosmwasm-std-1.5.4-dev-pow_in_range_control` |
| cosmwasm | `rust:CWA-2024-002` | `cosmwasm-std-1.5.4-dev-uint128_pow_overflow_wraps_silently` | executed | executed_without_impact | L4 | `tests::uint128_pow_overflow_wraps_silently` | `crates.io cosm` | `experiments_nonevm/rust__CWA-2024-002/cosmwasm-std-1.5.4-dev-uint128_pow_overflow_wraps_silently` |
| cosmwasm | `rust:CWA-2024-002` | `cosmwasm-std-1.5.4-dev-uint256_pow_overflow_wraps_silently` | executed | executed_without_impact | L4 | `tests::uint256_pow_overflow_wraps_silently` | `crates.io cosm` | `experiments_nonevm/rust__CWA-2024-002/cosmwasm-std-1.5.4-dev-uint256_pow_overflow_wraps_silently` |
| cosmwasm | `rust:CWA-2024-002` | `cosmwasm-std-1.5.4-dev-uint512_pow_overflow_wraps_silently` | executed | executed_without_impact | L4 | `tests::uint512_pow_overflow_wraps_silently` | `crates.io cosm` | `experiments_nonevm/rust__CWA-2024-002/cosmwasm-std-1.5.4-dev-uint512_pow_overflow_wraps_silently` |
| cosmwasm | `rust:CWA-2024-002` | `cosmwasm-std-1.5.4-release-int256_neg_min_wraps_silently` | executed | executed_without_impact | L4 | `tests::int256_neg_min_wraps_silently` | `crates.io cosm` | `experiments_nonevm/rust__CWA-2024-002/cosmwasm-std-1.5.4-release-int256_neg_min_wraps_silently` |
| cosmwasm | `rust:CWA-2024-002` | `cosmwasm-std-1.5.4-release-pow_in_range_control` | executed | executed_without_impact | L4 | `tests::pow_in_range_control` | `crates.io cosm` | `experiments_nonevm/rust__CWA-2024-002/cosmwasm-std-1.5.4-release-pow_in_range_control` |
| cosmwasm | `rust:CWA-2024-002` | `cosmwasm-std-1.5.4-release-uint128_pow_overflow_wraps_silently` | executed | executed_without_impact | L4 | `tests::uint128_pow_overflow_wraps_silently` | `crates.io cosm` | `experiments_nonevm/rust__CWA-2024-002/cosmwasm-std-1.5.4-release-uint128_pow_overflow_wraps_silently` |
| cosmwasm | `rust:CWA-2024-002` | `cosmwasm-std-1.5.4-release-uint256_pow_overflow_wraps_silently` | executed | executed_without_impact | L4 | `tests::uint256_pow_overflow_wraps_silently` | `crates.io cosm` | `experiments_nonevm/rust__CWA-2024-002/cosmwasm-std-1.5.4-release-uint256_pow_overflow_wraps_silently` |
| cosmwasm | `rust:CWA-2024-002` | `cosmwasm-std-1.5.4-release-uint512_pow_overflow_wraps_silently` | executed | executed_without_impact | L4 | `tests::uint512_pow_overflow_wraps_silently` | `crates.io cosm` | `experiments_nonevm/rust__CWA-2024-002/cosmwasm-std-1.5.4-release-uint512_pow_overflow_wraps_silently` |
| cosmwasm | `rust:CWA-2024-002` | `cosmwasm-std-2.0.1-dev-int256_neg_min_wraps_silently` | executed | executed_without_impact | L4 | `tests::int256_neg_min_wraps_silently` | `crates.io cosm` | `experiments_nonevm/rust__CWA-2024-002/cosmwasm-std-2.0.1-dev-int256_neg_min_wraps_silently` |
| cosmwasm | `rust:CWA-2024-002` | `cosmwasm-std-2.0.1-dev-pow_in_range_control` | executed | executed_without_impact | L4 | `tests::pow_in_range_control` | `crates.io cosm` | `experiments_nonevm/rust__CWA-2024-002/cosmwasm-std-2.0.1-dev-pow_in_range_control` |
| cosmwasm | `rust:CWA-2024-002` | `cosmwasm-std-2.0.1-dev-uint128_pow_overflow_wraps_silently` | executed | executed_without_impact | L4 | `tests::uint128_pow_overflow_wraps_silently` | `crates.io cosm` | `experiments_nonevm/rust__CWA-2024-002/cosmwasm-std-2.0.1-dev-uint128_pow_overflow_wraps_silently` |
| cosmwasm | `rust:CWA-2024-002` | `cosmwasm-std-2.0.1-dev-uint256_pow_overflow_wraps_silently` | executed | executed_without_impact | L4 | `tests::uint256_pow_overflow_wraps_silently` | `crates.io cosm` | `experiments_nonevm/rust__CWA-2024-002/cosmwasm-std-2.0.1-dev-uint256_pow_overflow_wraps_silently` |
| cosmwasm | `rust:CWA-2024-002` | `cosmwasm-std-2.0.1-dev-uint512_pow_overflow_wraps_silently` | executed | executed_without_impact | L4 | `tests::uint512_pow_overflow_wraps_silently` | `crates.io cosm` | `experiments_nonevm/rust__CWA-2024-002/cosmwasm-std-2.0.1-dev-uint512_pow_overflow_wraps_silently` |
| cosmwasm | `rust:CWA-2024-002` | `cosmwasm-std-2.0.1-release-int256_neg_min_wraps_silently` | executed | claim_reproduced | L5 | `tests::int256_neg_min_wraps_silently` | `crates.io cosm` | `experiments_nonevm/rust__CWA-2024-002/cosmwasm-std-2.0.1-release-int256_neg_min_wraps_silently` |
| cosmwasm | `rust:CWA-2024-002` | `cosmwasm-std-2.0.1-release-pow_in_range_control` | executed | executed_without_impact | L4 | `tests::pow_in_range_control` | `crates.io cosm` | `experiments_nonevm/rust__CWA-2024-002/cosmwasm-std-2.0.1-release-pow_in_range_control` |
| cosmwasm | `rust:CWA-2024-002` | `cosmwasm-std-2.0.1-release-uint128_pow_overflow_wraps_silently` | executed | claim_reproduced | L5 | `tests::uint128_pow_overflow_wraps_silently` | `crates.io cosm` | `experiments_nonevm/rust__CWA-2024-002/cosmwasm-std-2.0.1-release-uint128_pow_overflow_wraps_silently` |
| cosmwasm | `rust:CWA-2024-002` | `cosmwasm-std-2.0.1-release-uint256_pow_overflow_wraps_silently` | executed | claim_reproduced | L5 | `tests::uint256_pow_overflow_wraps_silently` | `crates.io cosm` | `experiments_nonevm/rust__CWA-2024-002/cosmwasm-std-2.0.1-release-uint256_pow_overflow_wraps_silently` |
| cosmwasm | `rust:CWA-2024-002` | `cosmwasm-std-2.0.1-release-uint512_pow_overflow_wraps_silently` | executed | claim_reproduced | L5 | `tests::uint512_pow_overflow_wraps_silently` | `crates.io cosm` | `experiments_nonevm/rust__CWA-2024-002/cosmwasm-std-2.0.1-release-uint512_pow_overflow_wraps_silently` |
| cosmwasm | `rust:CWA-2024-002` | `cosmwasm-std-2.0.2-dev-int256_neg_min_wraps_silently` | executed | executed_without_impact | L4 | `tests::int256_neg_min_wraps_silently` | `crates.io cosm` | `experiments_nonevm/rust__CWA-2024-002/cosmwasm-std-2.0.2-dev-int256_neg_min_wraps_silently` |
| cosmwasm | `rust:CWA-2024-002` | `cosmwasm-std-2.0.2-dev-pow_in_range_control` | executed | executed_without_impact | L4 | `tests::pow_in_range_control` | `crates.io cosm` | `experiments_nonevm/rust__CWA-2024-002/cosmwasm-std-2.0.2-dev-pow_in_range_control` |
| cosmwasm | `rust:CWA-2024-002` | `cosmwasm-std-2.0.2-dev-uint128_pow_overflow_wraps_silently` | executed | executed_without_impact | L4 | `tests::uint128_pow_overflow_wraps_silently` | `crates.io cosm` | `experiments_nonevm/rust__CWA-2024-002/cosmwasm-std-2.0.2-dev-uint128_pow_overflow_wraps_silently` |
| cosmwasm | `rust:CWA-2024-002` | `cosmwasm-std-2.0.2-dev-uint256_pow_overflow_wraps_silently` | executed | executed_without_impact | L4 | `tests::uint256_pow_overflow_wraps_silently` | `crates.io cosm` | `experiments_nonevm/rust__CWA-2024-002/cosmwasm-std-2.0.2-dev-uint256_pow_overflow_wraps_silently` |
| cosmwasm | `rust:CWA-2024-002` | `cosmwasm-std-2.0.2-dev-uint512_pow_overflow_wraps_silently` | executed | executed_without_impact | L4 | `tests::uint512_pow_overflow_wraps_silently` | `crates.io cosm` | `experiments_nonevm/rust__CWA-2024-002/cosmwasm-std-2.0.2-dev-uint512_pow_overflow_wraps_silently` |
| cosmwasm | `rust:CWA-2024-002` | `cosmwasm-std-2.0.2-release-int256_neg_min_wraps_silently` | executed | executed_without_impact | L4 | `tests::int256_neg_min_wraps_silently` | `crates.io cosm` | `experiments_nonevm/rust__CWA-2024-002/cosmwasm-std-2.0.2-release-int256_neg_min_wraps_silently` |
| cosmwasm | `rust:CWA-2024-002` | `cosmwasm-std-2.0.2-release-pow_in_range_control` | executed | executed_without_impact | L4 | `tests::pow_in_range_control` | `crates.io cosm` | `experiments_nonevm/rust__CWA-2024-002/cosmwasm-std-2.0.2-release-pow_in_range_control` |
| cosmwasm | `rust:CWA-2024-002` | `cosmwasm-std-2.0.2-release-uint128_pow_overflow_wraps_silently` | executed | executed_without_impact | L4 | `tests::uint128_pow_overflow_wraps_silently` | `crates.io cosm` | `experiments_nonevm/rust__CWA-2024-002/cosmwasm-std-2.0.2-release-uint128_pow_overflow_wraps_silently` |
| cosmwasm | `rust:CWA-2024-002` | `cosmwasm-std-2.0.2-release-uint256_pow_overflow_wraps_silently` | executed | executed_without_impact | L4 | `tests::uint256_pow_overflow_wraps_silently` | `crates.io cosm` | `experiments_nonevm/rust__CWA-2024-002/cosmwasm-std-2.0.2-release-uint256_pow_overflow_wraps_silently` |
| cosmwasm | `rust:CWA-2024-002` | `cosmwasm-std-2.0.2-release-uint512_pow_overflow_wraps_silently` | executed | executed_without_impact | L4 | `tests::uint512_pow_overflow_wraps_silently` | `crates.io cosm` | `experiments_nonevm/rust__CWA-2024-002/cosmwasm-std-2.0.2-release-uint512_pow_overflow_wraps_silently` |
| cosmwasm | `rust:CWA-2024-004` | `blocked-CWA-2024-004` | blocked | blocked | L1 | `-` | `cosmwasm-vm <1` | `experiments_nonevm/rust__CWA-2024-004/blocked-CWA-2024-004` |
| cosmwasm | `rust:CWA-2026-006` | `blocked-CWA-2026-006` | blocked | blocked | L1 | `-` | `wasmvm <=v3.0.` | `experiments_nonevm/rust__CWA-2026-006/blocked-CWA-2026-006` |
| cosmwasm | `rust:levana-2023-price-staleness` | `blocked-levana-2023-price-staleness` | blocked | blocked | L1 | `-` | `-` | `experiments_nonevm/rust__levana-2023-price-staleness/blocked-levana-2023-price-staleness` |
| solana_anchor | `rust:CVE-2026-45137` | `blocked-CVE-2026-45137` | blocked | blocked | L1 | `-` | `v1.0.1 (declar` | `experiments_nonevm/rust__CVE-2026-45137/blocked-CVE-2026-45137` |
| solana_anchor | `rust:GHSA-429q-fhh4-r6hj` | `blocked-GHSA-429q-fhh4-r6hj` | blocked | blocked | L1 | `-` | `1.0.0-rc.1 (af` | `experiments_nonevm/rust__GHSA-429q-fhh4-r6hj/blocked-GHSA-429q-fhh4-r6hj` |
| solana_anchor | `rust:GHSA-6px8-6mw3-4hx4` | `blocked-GHSA-6px8-6mw3-4hx4` | blocked | blocked | L1 | `-` | `v1.1.2 with fe` | `experiments_nonevm/rust__GHSA-6px8-6mw3-4hx4/blocked-GHSA-6px8-6mw3-4hx4` |
| sui_move | `move:CVE-2023-36184` | `blocked-CVE-2023-36184` | blocked | blocked | L1 | `-` | `Sui v1.2.0 (NV` | `experiments_nonevm/move__CVE-2023-36184/blocked-CVE-2023-36184` |
| sui_move | `move:CVE-2023-42374` | `blocked-CVE-2023-42374` | blocked | blocked | L1 | `-` | `Sui before v1.` | `experiments_nonevm/move__CVE-2023-42374/blocked-CVE-2023-42374` |
| sui_move | `move:cetus-checked-shlw` | `mask_era_4d09c8b-above_boundary_3x2pow192_truncates_to_ze` | executed | claim_reproduced | L5 | `integer_mate::nonevm_shlw_poc::nonevm_above_boundary_3x2pow192_truncates_to_zero` | `4d09c8ba052727` | `experiments_nonevm/move__cetus-checked-shlw/mask_era_4d09c8b-above_boundary_3x2pow192_truncates_to_ze` |
| sui_move | `move:cetus-checked-shlw` | `mask_era_4d09c8b-boundary_exactly_2pow192_truncates_to_ze` | executed | claim_reproduced | L5 | `integer_mate::nonevm_shlw_poc::nonevm_boundary_exactly_2pow192_truncates_to_zero` | `4d09c8ba052727` | `experiments_nonevm/move__cetus-checked-shlw/mask_era_4d09c8b-boundary_exactly_2pow192_truncates_to_ze` |
| sui_move | `move:cetus-checked-shlw` | `mask_era_4d09c8b-control_below_boundary_shifts_correctly` | executed | executed_without_impact | L4 | `integer_mate::nonevm_shlw_poc::nonevm_control_below_boundary_shifts_correctly` | `4d09c8ba052727` | `experiments_nonevm/move__cetus-checked-shlw/mask_era_4d09c8b-control_below_boundary_shifts_correctly` |
| sui_move | `move:cetus-checked-shlw` | `pr6_era_fc84a51-above_boundary_3x2pow192_truncates_to_ze` | executed | executed_without_impact | L4 | `integer_mate::nonevm_shlw_poc::nonevm_above_boundary_3x2pow192_truncates_to_zero` | `fc84a51c29fabf` | `experiments_nonevm/move__cetus-checked-shlw/pr6_era_fc84a51-above_boundary_3x2pow192_truncates_to_ze` |
| sui_move | `move:cetus-checked-shlw` | `pr6_era_fc84a51-boundary_exactly_2pow192_truncates_to_ze` | executed | claim_reproduced | L5 | `integer_mate::nonevm_shlw_poc::nonevm_boundary_exactly_2pow192_truncates_to_zero` | `fc84a51c29fabf` | `experiments_nonevm/move__cetus-checked-shlw/pr6_era_fc84a51-boundary_exactly_2pow192_truncates_to_ze` |
| sui_move | `move:cetus-checked-shlw` | `pr6_era_fc84a51-control_below_boundary_shifts_correctly` | executed | executed_without_impact | L4 | `integer_mate::nonevm_shlw_poc::nonevm_control_below_boundary_shifts_correctly` | `fc84a51c29fabf` | `experiments_nonevm/move__cetus-checked-shlw/pr6_era_fc84a51-control_below_boundary_shifts_correctly` |
| sui_move | `move:cetus-checked-shlw` | `pr7_fix_06660f7-above_boundary_3x2pow192_truncates_to_ze` | executed | executed_without_impact | L4 | `integer_mate::nonevm_shlw_poc::nonevm_above_boundary_3x2pow192_truncates_to_zero` | `06660f704c4ac1` | `experiments_nonevm/move__cetus-checked-shlw/pr7_fix_06660f7-above_boundary_3x2pow192_truncates_to_ze` |
| sui_move | `move:cetus-checked-shlw` | `pr7_fix_06660f7-boundary_exactly_2pow192_truncates_to_ze` | executed | executed_without_impact | L4 | `integer_mate::nonevm_shlw_poc::nonevm_boundary_exactly_2pow192_truncates_to_zero` | `06660f704c4ac1` | `experiments_nonevm/move__cetus-checked-shlw/pr7_fix_06660f7-boundary_exactly_2pow192_truncates_to_ze` |
| sui_move | `move:cetus-checked-shlw` | `pr7_fix_06660f7-control_below_boundary_shifts_correctly` | executed | executed_without_impact | L4 | `integer_mate::nonevm_shlw_poc::nonevm_control_below_boundary_shifts_correctly` | `06660f704c4ac1` | `experiments_nonevm/move__cetus-checked-shlw/pr7_fix_06660f7-control_below_boundary_shifts_correctly` |
| sui_move | `move:navi-lend-06-coin-type` | `blocked-navi-lend-06-coin-type` | blocked | blocked | L1 | `-` | `audit scope co` | `experiments_nonevm/move__navi-lend-06-coin-type/blocked-navi-lend-06-coin-type` |
| sui_move | `move:navi-pool-01-withdraw-permission` | `blocked-navi-pool-01-withdraw-permission` | blocked | blocked | L1 | `-` | `audit scope co` | `experiments_nonevm/move__navi-pool-01-withdraw-permission/blocked-navi-pool-01-withdraw-permission` |
| sui_move | `move:sui-amm-6.7-zero-liquidity` | `blocked-sui-amm-6.7-zero-liquidity` | blocked | blocked | L1 | `-` | `report scope: ` | `experiments_nonevm/move__sui-amm-6.7-zero-liquidity/blocked-sui-amm-6.7-zero-liquidity` |
| sui_move | `move:volo-os-vol-adv-00-roundupshares` | `blocked-volo-os-vol-adv-00-roundupshares` | blocked | blocked | L1 | `-` | `audit scope: V` | `experiments_nonevm/move__volo-os-vol-adv-00-roundupshares/blocked-volo-os-vol-adv-00-roundupshares` |
| sui_move | `move:zellic-3.1-usable-value-drop` | `blocked-zellic-3.1-usable-value-drop` | blocked | blocked | L1 | `-` | `report scope: ` | `experiments_nonevm/move__zellic-3.1-usable-value-drop/blocked-zellic-3.1-usable-value-drop` |
| sui_move | `move:zellic-3.2-control-flow-graph` | `blocked-zellic-3.2-control-flow-graph` | blocked | blocked | L1 | `-` | `report scope: ` | `experiments_nonevm/move__zellic-3.2-control-flow-graph/blocked-zellic-3.2-control-flow-graph` |

## Blockers as data

* `build_time_exceeds_budget: the claim is about the Rust Cairo VM (starkware-libs/cairo-vm) and its AIR/prover divergence; a scoped cargo test needs the cairo-vm workspace build plus a prover run` - 1 run(s)
* `build_time_exceeds_budget: the vulnerable CFG construction lives in move-language/move's bytecode verifier (Rust); the era-matching commits are pinned but the workspace build exceeds the per-run budget` - 1 run(s)
* `build_time_exceeds_pilot_budget: gas mispricing is observed through cosmwasm-vm's metered instantiate, which needs the full cosmwasm-vm/Wasmer build graph` - 1 run(s)
* `build_time_exceeds_pilot_budget: the claim is about the Wasmer Singlepass compiler embedded in wasmvm; it needs a cgo wasmvm build (Wasmer plus a Go host) before any assertion can run` - 1 run(s)
* `compile_failed: scarb scarb 2.20.1 (dd18779a1 2026-08-21) no longer accepts the plain #[test] attribute in a cairo-test target (the runner is deprecated in favour of snforge, and snforge needs universal-sierra-compiler, which is absent). First diagnostic: error[E2200]: Plugin diagnostic: Unsupported attribute.` - 1 run(s)
* `dependency_resolution_uncached_sui_framework_rev: same audited repository and same uncached framework pin as POOL-01` - 1 run(s)
* `dependency_resolution_uncached_sui_framework_rev: the Volo package pins an OtterSec-era Sui framework rev absent from the local cache` - 1 run(s)
* `dependency_resolution_uncached_sui_framework_rev: the audited Navi package pins a Sui framework revision that is not in the local git dependency cache, so resolving it means a full MystenLabs/sui clone` - 1 run(s)
* `native_runner_not_applicable: a crafted compressed script must be sent to a running Sui node; that needs a built sui-node binary plus a localnet, which exceeds this pilot's per-run budget` - 1 run(s)
* `native_runner_not_applicable: the affected component is NethermindEth/juno, a Go full node, not a Scarb package; reproducing the Sierra decompression loop needs a Go build of juno` - 1 run(s)
* `native_runner_not_applicable: the crash is reached through the JSON-RPC deserializer of a running node, not through `sui move test`` - 1 run(s)
* `native_runner_not_applicable_and_build_time_exceeds_budget: the fix is in MystenLabs/sui crates/sui-adapter (Rust full node); a scoped `cargo test` needs the whole Sui workspace build` - 1 run(s)
* `revision_unresolved: same CairoLib scope commit, same missing remote` - 1 run(s)
* `revision_unresolved: the Levana post-mortem names no commit, contract version or deployment, so no pin can be resolved` - 1 run(s)
* `revision_unresolved: the audit names CairoLib commits 99b1c0e3/d2d4dd7c but no public repository is identified in the source, so the pin cannot be resolved to a cloneable remote` - 1 run(s)
* `revision_unresolved: the post-mortem names no contract version, commit or deployment` - 1 run(s)
* `revision_unresolved: the report's Received Commit line is a 39-hex value with no leading 0x and is not resolvable, and the framework pin is not cached` - 1 run(s)
* `toolchain_missing: aptos-cli` - 1 run(s)
* `toolchain_missing: aptos-cli; and the component named by the record is the Aptos Move VM written in Rust, whose proof is a cargo test inside aptos-core (a workspace whose build exceeds this pilot's per-run budget)` - 1 run(s)
* `toolchain_missing: aptos-cli; the fix commit is in move-language/move's Rust bytecode verifier, so the assertion is a cargo test, not `aptos move test`` - 1 run(s)
* `toolchain_missing: solana-anchor (anchor-cli and solana-cli are both absent; `anchor test` needs the BPF build and a local solana-test-validator)` - 3 run(s)
* `toolchain_version_incompatible: the scarb in work/tools (scarb 2.20.1 (dd18779a1 2026-08-21)) cannot build v0.15.0, which declares cairo-version 2.7.0; 0 compiler diagnostics, no test binary built. First diagnostic: Error: `scarb metadata` exited with error` - 1 run(s)
* `toolchain_version_incompatible: the scarb in work/tools (scarb 2.20.1 (dd18779a1 2026-08-21)) cannot build v0.15.1, which declares cairo-version 2.7.0; 0 compiler diagnostics, no test binary built. First diagnostic: Error: `scarb metadata` exited with error` - 1 run(s)
* `toolchain_version_incompatible: the scarb in work/tools (scarb 2.20.1 (dd18779a1 2026-08-21)) cannot build v0.6.0, which declares cairo-version 2.7.0; 0 compiler diagnostics, no test binary built. First diagnostic: Error: `scarb metadata` exited with error` - 1 run(s)
* `toolchain_version_incompatible: v0.2.0 predates the Scarb workspace layout the 2.20.1 toolchain in work/tools expects, and no era-matching scarb is installed` - 1 run(s)

## Candidate pools that could not be pinned

Recomputed from `Vbeta\jsonl_vbeta\findings.jsonl` (metadata-only layer; no prose or code from it is copied into an artefact): 7060 findings, of which 943 are non-Solidity: unknown 730, rust 86, go 40, move 32, vyper 24, cairo 22, circom 4, typescript 2, leo 2, noir 1

395 of those carry a 40-hex sha anywhere in the record; the rest reference contest links with no upstream commit, so no pin can be resolved and they stay out of the executed set.

## Where the published scoping and the observed behaviour differ

Executed cells whose expectation (taken from the advisory's own version ranges and profiles) did not match what the runner reported. These stay `executed_without_impact`: the run happened, the claim did not reproduce in that configuration.

| record | pin | declared | assertion | expected | observed |
|---|---|---|---|---|---|
| `rust:CWA-2024-002` | 1.5.3 | declared_vulnerable | `tests::int256_neg_min_wraps_silently` | ok | failed |
| `rust:CWA-2024-002` | 1.5.3 | declared_vulnerable | `tests::uint128_pow_overflow_wraps_silently` | ok | failed |
| `rust:CWA-2024-002` | 1.5.3 | declared_vulnerable | `tests::uint256_pow_overflow_wraps_silently` | ok | failed |
| `rust:CWA-2024-002` | 1.5.3 | declared_vulnerable | `tests::uint512_pow_overflow_wraps_silently` | ok | failed |
| `rust:CWA-2024-002` | 2.0.1 | declared_vulnerable | `tests::int256_neg_min_wraps_silently` | ok | failed |
| `rust:CWA-2024-002` | 2.0.1 | declared_vulnerable | `tests::uint128_pow_overflow_wraps_silently` | ok | failed |
| `rust:CWA-2024-002` | 2.0.1 | declared_vulnerable | `tests::uint256_pow_overflow_wraps_silently` | ok | failed |
| `rust:CWA-2024-002` | 2.0.1 | declared_vulnerable | `tests::uint512_pow_overflow_wraps_silently` | ok | failed |

## Integrity

76 run directories validated; no errors.

## Scope honesty

A compiler success is recorded as L3 and is never promoted to L4+; an execution that does not reproduce the named claim stays at L4 (`executed_without_impact`). This pilot does not claim to be the first or only multi-VM executed security corpus; the comparison against public projects is in `reports/nonevm_landscape.md`.
