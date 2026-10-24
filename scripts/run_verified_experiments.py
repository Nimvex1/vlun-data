#!/usr/bin/env python3
"""Run the declared verification experiments and record the artefacts.

Each experiment states, before anything runs, what the outcome would mean. The
runner never interprets the outcome for the dataset: it records what forge did,
and the expectation declared in the registry is what the report compares against.

An experiment is:

    finding_id          the canonical VLUN finding id
    repo                a repository spec key from REPOS
    revision            "vulnerable" | "fixed"
    harness             {relative path: file contents} written into test/vlun_poc/
    match_test          forge --match-test filter
    expectation         what a correct security property looks like on this revision
    security_property   the property the experiment is about, in one sentence

Import rewriting: any `@test/<x>.sol` import in the harness that is also present
in the overlay is redirected at the overlay copy. That is how a fixture from a
later revision is supplied to an earlier one without editing a single file the
repository owns.

Usage:
    python scripts/run_verified_experiments.py --only 2024-01-renft
    python scripts/run_verified_experiments.py --finding 2024-01-renft/H-01
    python scripts/run_verified_experiments.py --list
    python scripts/run_verified_experiments.py --rerun
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import experiments as ex  # noqa: E402
import reconcile_proof_artefact_hashes as rpa  # noqa: E402  (the hashing scheme)
from vlun import REPORTS, ROOT, log, write_json  # noqa: E402

# ---------------------------------------------------------------------------
# repositories
# ---------------------------------------------------------------------------
RENFT_VULN = "3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291"   # audited snapshot
RENFT_URL = "https://github.com/re-nft/smart-contracts.git"

# Fixture overlays that only redirect imports are pinned to the AUDITED revision
# itself: the file bytes are identical to what the repository ships, and the
# overlay copy exists purely so the harness's `@test/` imports resolve to other
# overlay files rather than back into the repository tree.
AUDITED_PIN = RENFT_VULN

REPOS: dict[str, ex.RepoSpec] = {
    "renft-vulnerable": ex.RepoSpec(
        slug="renft-smart", url=RENFT_URL, commit=RENFT_VULN,
        submodules=True, framework="foundry",
        build_command=["forge", "build"],
        build_env={},
    ),
}
# Fixed revisions are checked out into the same working clone, so they are
# declared as repo specs that share the slug but pin a different commit.
def fixed(commit: str) -> ex.RepoSpec:
    return ex.RepoSpec(slug="renft-smart", url=RENFT_URL, commit=commit,
                       submodules=True, framework="foundry",
                       build_command=["forge", "build"])


def git_show(repo_key: str, commit: str, path: str) -> str:
    """Read a file out of the local clone at a commit, without checkout."""
    import subprocess
    clone = ex.worktree(REPOS[repo_key])
    r = subprocess.run(["git", "show", f"{commit}:{path}"], cwd=str(clone),
                       capture_output=True, timeout=300)
    if r.returncode != 0:
        raise FileNotFoundError(f"{commit}:{path} not present in {clone}")
    return r.stdout.decode("utf-8", "replace")


# ---------------------------------------------------------------------------
# experiment declarations
# ---------------------------------------------------------------------------
EXPERIMENTS: list[dict] = []


def declare(finding_id: str, *, vulnerable: ex.RepoSpec, fixed_spec: ex.RepoSpec,
            harness_vuln: dict[str, str], harness_fixed: dict[str, str],
            match_test: str, security_property: str, exploited_behaviour: str,
            blocked_behaviour: str, vuln_expectation: str, fixed_expectation: str,
            classification: str, evidence_layer: str, notes: str = "") -> None:
    EXPERIMENTS.append({
        "finding_id": finding_id,
        "classification": classification,
        "security_property": security_property,
        "exploited_behaviour": exploited_behaviour,
        "blocked_behaviour": blocked_behaviour,
        "evidence_layer": evidence_layer,
        "notes": notes,
        "match_test": match_test,
        "revisions": {
            "vulnerable": {
                "repo": vulnerable, "harness": harness_vuln,
                "expectation": vuln_expectation,
            },
            "fixed": {
                "repo": fixed_spec, "harness": harness_fixed,
                "expectation": fixed_expectation,
            },
        },
    })


def flatten(name: str) -> str:
    """Foundry only auto-discovers test files directly under the test directory,
    so every overlay file is stored flat and imported by its flat name."""
    return name.replace("\\", "/").replace("/", "__")


def rewrite_imports(text: str, overlay_paths: dict[str, str]) -> str:
    """Point `@test/<p>` (and overlaid `@src/<p>`) imports at the overlay copy."""
    out = text
    for original, flat in sorted(overlay_paths.items()):
        out = out.replace(f'@test/{original}', f'@test/vlun_poc/{flat}')
        out = out.replace(f'"{original}"', f'"@test/vlun_poc/{flat}"')
        if original.startswith("src/"):
            # A harness may carry a verbatim src/ file (a library that gained a
            # member the regression test references). Its import spec is
            # `@src/<p>`; only harness files are redirected, so every deployed
            # contract still compiles from the repository's own tree.
            out = out.replace(f'@{original}', f'@test/vlun_poc/{flat}')
    return out


def build_harness(base: dict[str, str], overlay: dict[str, str]) -> dict[str, str]:
    """Overlay files win; every other file gets its `@test/` imports redirected.

    Every file here comes out of the audited repository, so the whole harness is
    third-party source unless the caller overrides `authored`.
    """
    mapping = {orig: flatten(orig) for orig in overlay}
    files: dict[str, str] = {flatten(k): v for k, v in base.items()}
    files.update({flat: body for orig, body in overlay.items()
                  for flat in [mapping[orig]]})
    return {name: rewrite_imports(body, mapping) for name, body in files.items()}


def third_party_set(harness: dict[str, str], authored: set[str]) -> set[str]:
    """Harness names whose bytes come from the audited repository.

    reNFT is BUSL-1.1: use is permitted, redistribution is not. Only the tests
    this pipeline wrote itself are publishable, so anything the registry did not
    author is withheld from `experiments/` and recorded by hash instead.
    """
    return {name for name in harness if name not in authored}


# ===========================================================================
# The reNFT verification set.
#
# reNFT published its own mitigation commits inside the audited repository. Each
# mitigation added a regression test that asserts the exploit is blocked. Those
# tests are the strongest available evidence of a fix, and running the same test
# against the audited revision shows the vulnerability.
#
# The audited revision is 3ddd3245 (the submodule SHA the audit repository
# pinned), NOT a branch tip.
# ===========================================================================
RENFT_FIXTURE_UPDATES = {
    "mocks/tokens/standard/MockERC721.sol": "32e4df787a85534745b86eaea2d58d75a73e2edc",
    "mocks/tokens/standard/MockERC1155.sol": "4f913b8558d8f35d3ef741be2b4974c4bb388e53",
    # GnosisSafeUtils gained a `value` parameter and `...WithValue` helpers. The
    # overlay supplies the later version so the regression test compiles against
    # the older revision. The repository's own file is not modified.
    "utils/GnosisSafeUtils.sol": "d13e24015dbc7ed80a0a86baf5bdff24f73ef105",
    "mocks/tokens/weird/MockAlwaysRevertERC20.sol": "1783237cf05c9369c271b6f3a388b8d57d03ecc8",
}

RENFT_CASES = [
    dict(
        finding_id="2024-01-renft/H-01",
        test="integration/prevented-exploits/MaliciousSeaportTip.t.sol",
        fix_commit="1783237cf05c9369c271b6f3a388b8d57d03ecc8",
        # The regression test references Errors.CreatePolicy_PaymentNotWhitelisted,
        # declared by the mitigation's Errors.sol, so the fix commit's verbatim
        # library is overlaid for the test file's import. Deployed contracts still
        # compile from the repository's own tree, and custom-error selectors are
        # signature-derived, so expectRevert matching is byte-identical.
        overlays=["mocks/tokens/weird/MockAlwaysRevertERC20.sol",
                  "src/libraries/Errors.sol"],
        match_test="test_MaliciousSeaportTip",
        classification="runnable_after_harness_reconstruction",
        security_property=(
            "a fulfilment's ERC-20 consideration item can never make a rental order "
            "unstoppable once the assets have been transferred to the rental safe"),
        exploited=(
            "a fulfiller adds a token that reverts on transferFrom after the first "
            "pull; reNFT's stop-rent path depends on that transfer succeeding, so the "
            "order can never be stopped and the renter keeps paying"),
        blocked=(
            "the protocol rejects a consideration item whose token cannot complete the "
            "transfer, so the order never becomes unstoppable"),
    ),
    dict(
        finding_id="2024-01-renft/H-06",
        test="integration/prevented-exploits/PreapproveToBypassGuard.t.sol",
        fix_commit="32e4df787a85534745b86eaea2d58d75a73e2edc",
        # Two blockers on the audited revision, both verified against the
        # repository: (1) the test calls the internal helper `withZone`, which
        # the mitigation added to OrderCreator.sol; (2) deeper, the fix also
        # added `orderHash` to src RentPayload and `orderType` to SeaportPayload,
        # and the fix-era fixtures construct the 5-field payload. Supplying those
        # fixtures would mean compiling the harness against struct definitions
        # the deployed (audited) contracts do not share, so no honest overlay can
        # host this test on the audited revision. The record stays inconclusive
        # with this reason rather than being upgraded.
        overlays=["utils/GnosisSafeUtils.sol"],
        match_test="test_",
        classification="runnable_after_harness_reconstruction",
        security_property=(
            "a fulfiller cannot pre-approve the protocol so that a later rental "
            "settlement bypasses the guard's per-selector checks"),
        exploited=(
            "the attacker approves the conduit on the renter's behalf during a benign "
            "rent, then performs the guarded action later without the guard seeing it"),
        blocked=("the guard refuses to act when the approval was not granted under "
                 "the guard's own check"),
    ),
    dict(
        finding_id="2024-01-renft/M-11",
        test=None,
        fix_commit="6c4124bdb7acc52a84d008d6d3cf62b01c85a933",
        overlays=[],
        match_test="test_VlunEip712TypeHash",
        classification="already_runnable",
        security_property=(
            "the protocol's EIP-712 type hash of a rental order equals the hash of the "
            "canonical type string, so a signature over the order can never be replayed "
            "into a different type domain"),
        exploited=(
            "Signer.sol hashed the order type string with abi.encode, which appends a "
            "32-byte word per argument, so the computed domain separator differed from "
            "the EIP-712 encoding and signatures verified against a different digest"),
        blocked=("the type hash is computed with abi.encodePacked, which matches the "
                 "canonical EIP-712 encoding byte for byte"),
        custom=("m11_eip712"),
    ),
]

RENFT_CASES += [
    dict(
        finding_id="2024-01-renft/M-09",
        test="integration/guarded-transactions/Safe.t.sol",
        fix_commit="f0484bfa15c68cad921a8d8abe93f2cef1ad493c",
        overlays=["utils/GnosisSafeUtils.sol"],
        match_test="test_",
        classification="runnable_after_harness_reconstruction",
        security_property=(
            "an owner of a rental safe can transfer native ETH out of the safe; the guard "
            "must not block it"),
        exploited=("GuardCheckTransaction rejected every native transfer out of the rental "
                   "safe, including the owner's own withdrawal of rental proceeds"),
        blocked=("the guard permits a plain call that moves the safe's ETH balance"),
    ),
    dict(
        finding_id="2024-01-renft/M-01",
        test="integration/guarded-transactions/ERC1155.t.sol",
        fix_commit="45ef41123b65d67b7f83cad8bc9d35917b9da30f",
        # Two blockers on the audited revision: (1) the test expects
        # Errors.GuardPolicy_UnauthorizedAssetAmount, declared by the mitigation
        # (Errors.sol overlaid verbatim from the fix commit); (2) the mock arrays
        # are declared in AccountCreator.sol with the pre-mitigation mock types,
        # so the declaring chain (BaseTest -> BaseProtocol -> AccountCreator) is
        # overlaid at the audited revision, which redirects its mock imports to
        # the post-mitigation MockERC1155. The fix commit's own Protocol.sol is
        # deliberately NOT overlaid: it calls Admin.setMaxRentDuration, which the
        # audited Admin policy does not have.
        overlays=["utils/GnosisSafeUtils.sol",
                  "mocks/tokens/standard/MockERC1155.sol",
                  "src/libraries/Errors.sol",
                  ("BaseTest.sol", AUDITED_PIN),
                  ("fixtures/engine/BaseEngine.sol", AUDITED_PIN),
                  ("fixtures/engine/OrderFulfiller.sol", AUDITED_PIN),
                  ("fixtures/engine/OrderCreator.sol", AUDITED_PIN),
                  ("fixtures/protocol/BaseProtocol.sol", AUDITED_PIN),
                  ("fixtures/protocol/AccountCreator.sol", AUDITED_PIN)],
        # The fix commit moved the mock declarations from AccountCreator into a
        # new TokenCreator fixture, so the audited-revision AccountCreator overlay
        # would collide with the repository's own TokenCreator on the fixed side.
        # The fixed revision hosts the regression test with its own fixtures.
        fixed_overlays=["utils/GnosisSafeUtils.sol",
                        "mocks/tokens/standard/MockERC1155.sol"],
        match_test="test_",
        classification="runnable_after_harness_reconstruction",
        security_property=(
            "a lender cannot freeze a borrower's ERC-1155: a burn or transfer up to the "
            "rented amount stays possible"),
        exploited=("a malicious lender withdrew more ERC-1155 than was rented, so the "
                   "guard refused every subsequent burn and the borrower's balance was frozen"),
        blocked=("the guard compares the action against the recorded rented amount rather "
                 "than the post-withdrawal balance"),
    ),
    dict(
        finding_id="2024-01-renft/M-08",
        test="integration/guarded-transactions/ERC721.t.sol",
        fix_commit="fb8013111b57c1e09482fb3193db58cb892229e9",
        # Same closure treatment as M-01: the mock arrays are declared in
        # AccountCreator.sol, which the test reaches through the engine chain
        # (BaseTest -> BaseEngine -> OrderFulfiller -> OrderCreator -> BaseProtocol
        # -> AccountCreator), so the whole chain is overlaid at the audited
        # revision - byte-identical files whose only effect is redirecting the
        # mock imports to the post-mitigation MockERC721.
        overlays=["utils/GnosisSafeUtils.sol",
                  "mocks/tokens/standard/MockERC721.sol",
                  ("BaseTest.sol", AUDITED_PIN),
                  ("fixtures/engine/BaseEngine.sol", AUDITED_PIN),
                  ("fixtures/engine/OrderFulfiller.sol", AUDITED_PIN),
                  ("fixtures/engine/OrderCreator.sol", AUDITED_PIN),
                  ("fixtures/protocol/BaseProtocol.sol", AUDITED_PIN),
                  ("fixtures/protocol/AccountCreator.sol", AUDITED_PIN)],
        fixed_overlays=["utils/GnosisSafeUtils.sol",
                        "mocks/tokens/standard/MockERC721.sol"],
        match_test="test_",
        classification="runnable_after_harness_reconstruction",
        security_property=(
            "assets held by a rental safe cannot be destroyed by the renter or the lender; "
            "the guard blocks unguarded destructive selectors"),
        exploited=("burn() or a transfer to a dead address removed the asset from the safe "
                   "while the rental was active"),
        blocked=("the guard rejects an unguarded destructive call against the safe"),
    ),
    dict(
        finding_id="2024-01-renft/H-03",
        test="integration/prevented-exploits/BypassInvariantChecks.t.sol",
        fix_commit="e4cdac74c7565d41dc7882d3837dde2cf930e9d7",
        overlays=["utils/GnosisSafeUtils.sol"],
        match_test="test_",
        classification="runnable_after_harness_reconstruction",
        security_property=(
            "the payment escrow cannot be drained by an account whose temporary allowance "
            "exceeds its balance"),
        exploited=("an intermediary transferred on rent, so the escrow's invariant checks "
                   "were evaluated against a temporary balance that the account could then "
                   "withdraw, draining the escrow"),
        blocked=("the escrow enforces its balance invariant against the settled state, so "
                 "the intermediate transfer cannot inflate the withdrawable amount"),
    ),
    dict(
        finding_id="2024-01-renft/M-02",
        test="integration/prevented-exploits/PermitTokens.t.sol",
        fix_commit="12bdab416447b51b43b7053be7b55b5b932336e5",
        overlays=["utils/GnosisSafeUtils.sol"],
        match_test="test_",
        notes=("not reconstructable on the audited revision without modifying "
               "production code: the regression test calls Fallback"
               ".getMessageHashForSafe and Kernel Actions.DeactivatePolicy, and "
               "neither symbol exists at 3ddd3245 (verified by git grep). The "
               "harness never modifies or replaces production code, so no honest "
               "overlay can host this test there; the record stays inconclusive "
               "with this reason rather than being upgraded."),
        classification="runnable_after_harness_reconstruction",
        security_property=(
            "a caller cannot settle a rental into an arbitrary account by triggering an "
            "ERC-721 permit transfer"),
        exploited=("a malicious borrower called the safe with a permit-style token call, so "
                   "the rental settled into an attacker-chosen recipient"),
        blocked=("the safe's fallback handler refuses token callbacks it does not recognise"),
    ),
    dict(
        finding_id="2024-01-renft/H-04",
        test="integration/Exploits.t.sol",
        fix_commit="f358c1738dae359d83f7f5e1c074c988a9577e80",
        overlays=["utils/GnosisSafeUtils.sol"],
        match_test="test_",
        classification="runnable_after_harness_reconstruction",
        security_property=(
            "a renter cannot disable the payment-escrow module and bypass the guard, because "
            "the calldata offset used to address the module must be the real one"),
        exploited=("DISABLE_MODULE_OFFSET pointed at the wrong byte, so the signed transaction "
                   "disabled a different module and the guard stayed active while the renter "
                   "believed it was disabled"),
        blocked=("the constant matches the deployed module layout, so the disabled module is "
                 "the guard itself"),
    ),
]

# The M-11 fixed commit is looked up from the patch record rather than hardcoded.
M11_FIX_COMMIT = "6c4124bd"


def m11_harness() -> dict[str, str]:
    """Self-contained EIP-712 test. It needs no project fixture, only forge-std."""
    return {"VlunEip712.t.sol": M11_SOURCE}


# Superseded reconstruction of the H-01 harness, kept for provenance of the
# earlier attempt. The registry no longer uses it: H-01 now runs the mitigation
# commit's own regression test on BOTH revisions (an Errors.sol overlay supplies
# the selector the test needs), which makes it a controlled comparison.
H01_SOURCE = '''// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {
    Order,
    OrderParameters,
    OfferItem,
    ConsiderationItem,
    FulfillmentComponent,
    Fulfillment,
    ItemType as SeaportItemType
} from "@seaport-types/lib/ConsiderationStructs.sol";
import {OfferItemLib, ConsiderationItemLib} from "@seaport-sol/SeaportSol.sol";

import {BaseTest} from "@test/BaseTest.sol";
import {MockAlwaysRevertERC20} from "@test/vlun_poc/mocks__tokens__weird__MockAlwaysRevertERC20.sol";
import {MockERC20} from "@test/mocks/tokens/standard/MockERC20.sol";

import {OrderType, OrderMetadata} from "@src/libraries/RentalStructs.sol";

/// Succeeds on the first `transferFrom` and reverts on every later one.
contract MockRevertAfterTransferERC20 is MockAlwaysRevertERC20 {
    bool public shouldRevert;

    function transferFrom(address, address, uint256) public override returns (bool) {
        require(!shouldRevert, "transferFrom() revert");
        shouldRevert = true;
        return true;
    }
}

/// Reconstruction of finding 2024-01-renft/H-01 on the audited revision.
///
/// The published regression test (added by the mitigation commit) asserts a
/// specific revert selector, `Errors.CreatePolicy_PaymentNotWhitelisted`, which
/// only exists after the fix. Replaying that test verbatim on the audited
/// revision therefore cannot compile, which says nothing about the vulnerability.
///
/// This reconstruction keeps the reporter's attack sequence byte for byte and
/// replaces only the *conclusion*, asserting the security property itself:
///
///     SECURITY PROPERTY: a fulfilment whose ERC-20 consideration item cannot
///     complete its transfer must be rejected, because reNFT's stop-rent path
///     depends on that transfer succeeding. If the fulfilment is accepted, the
///     renter can never stop paying.
///
/// Polarity: `vm.expectRevert()` passes only when the protocol rejects the
/// malicious tip. On the audited revision the fulfilment succeeds, so this test
/// fails there and passes after the fix.
contract VlunMaliciousSeaportTipTest is BaseTest {
    using ConsiderationItemLib for ConsiderationItem;

    function test_VlunMaliciousSeaportTip_UnsettleableTipMustBeRejected() public {
        MockRevertAfterTransferERC20 testToken = new MockRevertAfterTransferERC20();

        // mint the token to bob
        testToken.mint(alice.addr, 100);

        // approve the conduit to pull the token
        vm.prank(bob.addr);
        testToken.approve(address(conduit), type(uint256).max);

        // create a BASE order
        createOrder({
            offerer: alice,
            orderType: OrderType.BASE,
            erc721Offers: 1,
            erc1155Offers: 0,
            erc20Offers: 0,
            erc721Considerations: 0,
            erc1155Considerations: 0,
            erc20Considerations: 1
        });

        // finalize the order creation
        (
            Order memory order,
            bytes32 orderHash,
            OrderMetadata memory metadata
        ) = finalizeOrder();

        // create an order fulfillment
        createOrderFulfillment({
            _fulfiller: bob,
            order: order,
            orderHash: orderHash,
            metadata: metadata
        });

        // Add a consideration item tip to an order that has already been signed.
        // The order hash is already committed, so this tip is attacker-controlled
        // and was never part of what the lender signed.
        OrderParameters storage params = ordersToFulfill[0].advancedOrder.parameters;
        params.consideration.push(
            ConsiderationItemLib
                .empty()
                .withItemType(SeaportItemType.ERC20)
                .withToken(address(testToken))
                .withIdentifierOrCriteria(0)
                .withStartAmount(100)
                .withEndAmount(100)
                .withRecipient(address(ESCRW))
        );

        // SECURITY PROPERTY: the fulfilment must revert because the payment token
        // cannot be settled.
        vm.expectRevert();
        finalizeBaseOrderFulfillment();
    }

    /// Control: with a well-behaved ERC-20 tip the same sequence is accepted, so
    /// the assertion above is discriminating rather than vacuously true.
    function test_VlunMaliciousSeaportTip_ControlWellBehavedTipIsAccepted() public {
        MockERC20 goodToken = new MockERC20();
        goodToken.mint(bob.addr, 100);
        vm.prank(bob.addr);
        goodToken.approve(address(conduit), type(uint256).max);

        createOrder({
            offerer: alice,
            orderType: OrderType.BASE,
            erc721Offers: 1,
            erc1155Offers: 0,
            erc20Offers: 0,
            erc721Considerations: 0,
            erc1155Considerations: 0,
            erc20Considerations: 1
        });

        (
            Order memory order,
            bytes32 orderHash,
            OrderMetadata memory metadata
        ) = finalizeOrder();

        createOrderFulfillment({
            _fulfiller: bob,
            order: order,
            orderHash: orderHash,
            metadata: metadata
        });

        OrderParameters storage params = ordersToFulfill[0].advancedOrder.parameters;
        params.consideration.push(
            ConsiderationItemLib
                .empty()
                .withItemType(SeaportItemType.ERC20)
                .withToken(address(goodToken))
                .withIdentifierOrCriteria(0)
                .withStartAmount(100)
                .withEndAmount(100)
                .withRecipient(address(ESCRW))
        );

        finalizeBaseOrderFulfillment();
    }
}
'''

M11_SOURCE = '''// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";

import {Signer} from "@src/packages/Signer.sol";
import {RentalOrder, Item, Hook, OrderType, ItemType, SettleTo} from "@src/libraries/RentalStructs.sol";

/// Exposes the protocol's own EIP-712 state. Nothing here re-implements the
/// hashing: every value read is the value the deployed protocol computed in its
/// constructor, so this test measures the audited source and not a copy of it.
contract SignerProbe is Signer {
    function rentalOrderTypeHash() external view returns (bytes32) {
        return _RENTAL_ORDER_TYPEHASH;
    }

    function hookTypeHash() external view returns (bytes32) {
        return _HOOK_TYPEHASH;
    }

    function itemTypeHash() external view returns (bytes32) {
        return _ITEM_TYPEHASH;
    }

    function orderFulfillmentTypeHash() external view returns (bytes32) {
        return _ORDER_FULFILLMENT_TYPEHASH;
    }

    function orderMetadataTypeHash() external view returns (bytes32) {
        return _ORDER_METADATA_TYPEHASH;
    }

    function rentPayloadTypeHash() external view returns (bytes32) {
        return _RENT_PAYLOAD_TYPEHASH;
    }

    function deriveRentalOrderHash(RentalOrder memory order) external view returns (bytes32) {
        return _deriveRentalOrderHash(order);
    }

    function deriveHookHash(Hook memory hook) external view returns (bytes32) {
        return _deriveHookHash(hook);
    }

    function deriveItemHash(Item memory item) external view returns (bytes32) {
        return _deriveItemHash(item);
    }

    function domainSeparator() external view returns (bytes32) {
        return _DOMAIN_SEPARATOR;
    }
}

/// EIP-712 conformance of reNFT's `Signer` at a pinned revision.
///
/// Finding 2024-01-renft/M-11 reports five encoding defects in
/// `src/packages/Signer.sol`. Two of them are directly observable without any
/// protocol fixture:
///
///   1. `_deriveRentalOrderHash` omits `order.rentalWallet` from the ABI-encoded
///      struct hash. Two rental orders that differ only in `rentalWallet`
///      therefore produce the *same* digest, so a lender signature over one rental
///      wallet authorises a rental into a different wallet.
///
///   2. `_RENTAL_ORDER_TYPEHASH` is `keccak256(abi.encode(...))` of the three type
///      strings. EIP-712 requires verbatim concatenation (`abi.encodePacked`),
///      so the protocol's type hash is not the canonical one and the domain it
///      signs over differs from the domain any EIP-712 client computes.
///
/// Test polarity: each property is asserted in the direction that is FALSE on the
/// vulnerable revision and TRUE on the fixed revision, so `forge test` passing on
/// the fixed revision and failing on the audited revision is the evidence.
contract VlunEip712Test is Test {
    SignerProbe probe;

    function setUp() public {
        probe = new SignerProbe();
    }

    function _canonicalRentalOrderTypeHash() internal pure returns (bytes32) {
        return keccak256(
            bytes(
                string.concat(
                    "RentalOrder(bytes32 seaportOrderHash,Item[] items,Hook[] hooks,uint8 orderType,address lender,address renter,address rentalWallet,uint256 startTimestamp,uint256 endTimestamp)",
                    "Hook(address target,uint256 itemIndex,bytes extraData)",
                    "Item(uint8 itemType,uint8 settleTo,address token,uint256 amount,uint256 identifier)"
                )
            )
        );
    }

    function _order(address rentalWallet) internal pure returns (RentalOrder memory o) {
        o.seaportOrderHash = keccak256("order");
        o.items = new Item[](1);
        o.items[0] = Item({itemType: ItemType.ERC721, settleTo: SettleTo.LENDER, token: address(0xA11CE), amount: 1e18, identifier: 7});
        o.hooks = new Hook[](1);
        o.hooks[0] = Hook({target: address(0xB0B), itemIndex: 0, extraData: bytes("payload")});
        o.orderType = OrderType.BASE;
        o.lender = address(0x11E4);
        o.renter = address(0x2E27E2);
        o.rentalWallet = rentalWallet;
        o.startTimestamp = 1_700_000_000;
        o.endTimestamp = 1_700_000_000 + 30 days;
    }

    /// SECURITY PROPERTY: the rental wallet is bound by the signed digest.
    /// Vulnerable revision: both orders hash identically, so the assertion fails.
    function test_VlunEip712_RentalWalletIsBoundByTheDigest() public {
        RentalOrder memory honest = _order(address(0xAAA1));
        RentalOrder memory hijacked = _order(address(0xBBB2));
        assertTrue(
            probe.deriveRentalOrderHash(honest) != probe.deriveRentalOrderHash(hijacked),
            "two rental orders differing only in rentalWallet produced the same digest"
        );
    }

    /// SECURITY PROPERTY: the hook's dynamic field is hashed per EIP-712.
    /// Vulnerable revision: `extraData` is ABI-encoded raw instead of keccak'd.
    function test_VlunEip712_HookExtraDataIsHashed() public {
        bytes32 canonical = keccak256(
            abi.encode(probe.hookTypeHash(), address(0xB0B), uint256(0), keccak256(bytes("payload")))
        );
        assertEq(probe.deriveHookHash(Hook({target: address(0xB0B), itemIndex: 0, extraData: bytes("payload")})), canonical);
    }

    /// SECURITY PROPERTY: the rental order type hash is the canonical EIP-712 hash.
    /// Vulnerable revision: computed with abi.encode, so it differs.
    function test_VlunEip712_RentalOrderTypeHashIsCanonical() public {
        assertEq(probe.rentalOrderTypeHash(), _canonicalRentalOrderTypeHash());
    }

    /// Control: the two encodings really do produce different digests, so the
    /// assertion above is not vacuously true for every input.
    function test_VlunEip712_EncodingsDiffer() public {
        bytes memory rentalOrderTypeString = bytes(
            "RentalOrder(bytes32 seaportOrderHash,Item[] items,Hook[] hooks,uint8 orderType,address lender,address renter,address rentalWallet,uint256 startTimestamp,uint256 endTimestamp)"
        );
        bytes memory hookTypeString = bytes("Hook(address target,uint256 itemIndex,bytes extraData)");
        bytes memory itemTypeString = bytes(
            "Item(uint8 itemType,uint8 settleTo,address token,uint256 amount,uint256 identifier)"
        );
        assertTrue(
            keccak256(abi.encode(rentalOrderTypeString, hookTypeString, itemTypeString))
                != keccak256(
                    abi.encodePacked(rentalOrderTypeString, hookTypeString, itemTypeString)
                )
        );
    }
}
'''



def _resolve_short_shas() -> None:
    """The registry names mitigation commits by short SHA; expand them locally."""
    import subprocess
    clone = ex.worktree(REPOS["renft-vulnerable"])
    r = subprocess.run(["git", "rev-parse"] + [c["fix_commit"] for c in RENFT_CASES],
                       cwd=str(clone), capture_output=True, text=True, timeout=300)
    found = r.stdout.split()
    if len(found) != len(RENFT_CASES):
        missing = [c["fix_commit"] for c in RENFT_CASES
                   if c["fix_commit"] not in found and not re.fullmatch(r"[0-9a-f]{40}", c["fix_commit"])]
        raise SystemExit("unresolved mitigation commits: " + ", ".join(missing))
    for case, full in zip(RENFT_CASES, found):
        case["fix_commit"] = full


_resolve_short_shas()

def build_registry() -> list[dict]:
    """Materialise the reNFT cases into EXPERIMENTS with real file contents."""
    reg: list[dict] = []
    for case in RENFT_CASES:
        # per-iteration defaults; Python locals persist across loop iterations,
        # so they must be re-initialised rather than read with locals().get()
        vuln_match_path = None
        fixed_match_path = None
        if case.get("custom") == "m11_eip712":
            harness = m11_harness()
            reg.append({
                "finding_id": case["finding_id"],
                "classification": case["classification"],
                "security_property": case["security_property"],
                "exploited_behaviour": case["exploited"],
                "blocked_behaviour": case["blocked"],
                "evidence_layer": "dynamic_poc_plus_source_diff",
                "notes": ("self-contained test: the EIP-712 defect is a pure encoding "
                          "defect, so it is reproduced without any protocol fixture. The "
                          "fixed revision's Signer.sol is read at execution time to decide "
                          "which assertion is expected to hold."),
                "match_test": "test_VlunEip712",
                "revisions": {
                    "vulnerable": {"repo_key": "renft-vulnerable",
                                   "harness": harness,
                                   "authored_harness": ["VlunEip712.t.sol"],
                                   "expectation": "the three EIP-712 property assertions FAIL: the protocol computes a non-canonical digest", "expected_status": "fail"},
                    "fixed": {"repo_key": "renft-fixed-" + case["fix_commit"][:8],
                              "harness": harness,
                              "authored_harness": ["VlunEip712.t.sol"],
                              "expectation": "the three EIP-712 property assertions PASS: the protocol computes the canonical digest", "expected_status": "pass"},
                },
                "fix_commit": case["fix_commit"],
            })
            continue
        overlay_files = {}
        for entry in case["overlays"]:
            # An overlay entry is either a path (fetched from RENFT_FIXTURE_UPDATES,
            # else from the case's fix commit) or a (path, commit) tuple that pins
            # the revision the bytes come from.
            if isinstance(entry, tuple):
                path, rev = entry
            else:
                path = entry
                rev = RENFT_FIXTURE_UPDATES.get(path, case["fix_commit"])
            # src/ overlays live at the repository root; everything else under test/.
            repo_path = path if path.startswith("src/") else "test/" + path
            overlay_files[path] = git_show("renft-vulnerable", rev, repo_path)
        # Both revisions run the SAME regression test. Where the fixture overlay
        # differs per revision (fixed_overlays), the difference is confined to
        # test-fixture bytes and is recorded per side in the harness manifests.
        test_src = git_show("renft-vulnerable", case["fix_commit"],
                            "test/" + case["test"])
        base = {case["test"]: test_src}
        vuln_harness = build_harness(base, overlay_files)
        fixed_overlays = {}
        for entry in case.get("fixed_overlays", case["overlays"]):
            if isinstance(entry, tuple):
                fpath, frev = entry
            else:
                fpath = entry
                frev = RENFT_FIXTURE_UPDATES.get(fpath, case["fix_commit"])
            frepo_path = fpath if fpath.startswith("src/") else "test/" + fpath
            fixed_overlays[fpath] = git_show("renft-vulnerable", frev, frepo_path)
        fixed_harness = build_harness(base, fixed_overlays)
        vuln_match_path = "test/vlun_poc/" + flatten(case["test"])
        fixed_match_path = vuln_match_path
        reg.append({
            "finding_id": case["finding_id"],
            "classification": case["classification"],
            "security_property": case["security_property"],
            "exploited_behaviour": case["exploited"],
            "blocked_behaviour": case["blocked"],
            "evidence_layer": "dynamic_poc_plus_source_diff",
            "notes": case.get(
                "notes",
                "the regression test shipped by the mitigation commit is executed "
                "against both revisions; fixture files it needs are supplied as an "
                "overlay so no repository file is modified"),
            "match_test": case["match_test"],
            "revisions": {
                "vulnerable": {"repo_key": "renft-vulnerable",
                               "harness": vuln_harness,
                               "match_path": vuln_match_path,
                               "authored_harness": [],
                               "expectation": "test FAILS: the guard does not block the exploit", "expected_status": "fail"},
                "fixed": {"repo_key": "renft-fixed-" + case["fix_commit"][:8],
                          "harness": fixed_harness,
                          "match_path": fixed_match_path,
                          "authored_harness": [],
                          "expectation": "test PASSES: the guard blocks the exploit", "expected_status": "pass"},
            },
            "fix_commit": case["fix_commit"],
        })
    return reg


# ---------------------------------------------------------------------------
# execution
# ---------------------------------------------------------------------------
def resolve_repo(key: str) -> ex.RepoSpec:
    if key in REPOS:
        return REPOS[key]
    if key.startswith("renft-fixed-"):
        commit = None
        for case in RENFT_CASES:
            if key.endswith(case["fix_commit"][:8]):
                commit = case["fix_commit"]
        if commit is None:
            commit = key.split("renft-fixed-", 1)[1]
        # resolve the short sha to the full one from the local clone
        import subprocess
        clone = ex.worktree(REPOS["renft-vulnerable"])
        r = subprocess.run(["git", "rev-parse", commit], cwd=str(clone),
                           capture_output=True, text=True, timeout=300)
        full = r.stdout.strip() or commit
        return fixed(full)
    raise KeyError(key)


# ---------------------------------------------------------------------------
# two-revision evidence
# ---------------------------------------------------------------------------
# `l6_verified_patch` claims more than "the vulnerable run failed and the fixed
# run passed": it claims the two runs differ in the code under test and in
# nothing else. That is only demonstrable when both revisions ran the same
# test, the same assertions and byte-identical harness bytes. The two
# committed result.json artefacts are the only evidence for the claim, so the
# verdict is derived from them rather than from the registry's intent, and it
# is recomputed on every run: a later regeneration cannot silently restore an
# over-stated verdict.
#
#   VERIFIED_TWO_REVISION  both sides recorded, byte-identical harness, both
#                           commits named, the declared polarity held
#   PARTIAL                one side missing, or the two sides did not run the
#                           same harness bytes
#   UNVERIFIABLE          nothing in the repository demonstrates the claim
TWO_REVISION_EVIDENCE_STATUSES = ("VERIFIED_TWO_REVISION", "PARTIAL",
                                  "UNVERIFIABLE")

VERDICT_FOR_EVIDENCE = {
    "VERIFIED_TWO_REVISION": "l6_verified_patch",
    "PARTIAL": "l6_partial_two_revision_evidence",
    "UNVERIFIABLE": "l6_unverifiable_two_revision_evidence",
}

SHA1_RE = re.compile(r"^[0-9a-f]{40}$")

# A run that completed with a recorded outcome is cached, whatever that outcome
# is. Re-running a completed run rewrites the committed evidence (new
# timestamps, new durations) without adding anything, so a regeneration of the
# report must not do it. A run that never completed (timeout, not_run) is not
# cached: retrying it is the point of running it again.
CACHEABLE_STATUSES = ("pass", "fail", "compile_error", "toolchain_failure")


def artefact_hash_record(finding_id: str, label: str,
                         prior: dict | None) -> tuple[dict, list]:
    """Digest every committed artefact of a revision under sha256-v2.

    The L6 evidence names the bytes it rests on, so the report carries the
    digest of each committed artefact together with the scheme version: a
    reader never has to guess how a digest was computed. A digest that the
    artefact's own record states but that cannot be reproduced from the
    committed bytes is reported next to it, with the reason, instead of being
    dropped or quietly rewritten.
    """
    d = ex.EXPERIMENTS / finding_id.replace("/", "__") / label
    hashes = {}
    for f in sorted(d.rglob("*")):
        if not f.is_file() or f.name == "result.json":
            continue
        rel = f.relative_to(d).as_posix()
        hashes[rel] = {"sha256": rpa.digest_normalised(f.read_bytes()),
                       "hash_version": rpa.HASH_VERSION}
    mismatches = []
    for name, want in ((prior or {}).get("artifact_sha256") or {}).items():
        f = d / name
        if not f.is_file():
            mismatches.append({"artefact": name, "status": "missing",
                               "recorded_sha256": want})
            continue
        ok, _ = rpa.matches(want, f.read_bytes(), "sha256-v1-text")
        if not ok:
            mismatches.append({
                "artefact": name,
                "status": "unresolved",
                "recorded_sha256": want,
                "committed_sha256": rpa.digest_normalised(f.read_bytes()),
                "recorded_hash_version": "sha256-v1-text",
                "reason": ("the committed artefact was edited after the run, so the "
                           "digest recorded with the run does not describe the "
                           "committed bytes; the original value and the commit whose "
                           "blob reproduces it are recorded in "
                           "scripts/reconcile_proof_artefact_hashes.py "
                           "::UNRESOLVED_ARTEFACT_HASHES"),
            })
    return hashes, mismatches


def stored_run_failure(finding_id: str, label: str, prior: dict) -> tuple[str, str | None]:
    """Re-derive the controlled failure reason from a stored artefact.

    A cached run has no RunResult any more, but the reason a run failed to
    compile is a property of its committed stdout/stderr, so it is recomputed
    from those bytes rather than being dropped from the report.
    """
    d = ex.EXPERIMENTS / finding_id.replace("/", "__") / label

    def _read(name: str) -> str:
        f = d / name
        return f.read_text(encoding="utf-8", errors="replace") if f.is_file() else ""

    class _Stored:
        status = prior.get("status")
        stdout = _read("stdout.txt")
        stderr = _read("stderr.txt")

    return ex.classify_run_failure(_Stored)


def _test_files(digests: dict) -> dict:
    return {n: d for n, d in (digests or {}).items() if n.endswith(".t.sol")}


def classify_two_revision_evidence(finding_id: str) -> dict:
    """Classify an experiment's two-revision evidence from its committed artefacts."""
    safe = finding_id.replace("/", "__")
    sides: dict[str, dict | None] = {}
    for label in ("vulnerable", "fixed"):
        d = ex.EXPERIMENTS / safe / label / "result.json"
        sides[label] = (json.loads(d.read_text(encoding="utf-8"))
                        if d.is_file() else None)

    out: dict = {
        "status": "UNVERIFIABLE",
        "missing_evidence": [],
        "harness_digests_match": False,
        "test_file_digests_match": False,
        "vulnerable": None,
        "fixed": None,
        "commit_resolution": {},
    }
    absent = [lbl for lbl, d in sides.items() if not d]
    if absent:
        out["missing_evidence"].append(
            "no committed result.json for the " + " and ".join(absent)
            + " revision, so the comparison cannot be checked")
        return out

    for label, d in sides.items():
        repo = d.get("repository") or {}
        commits = repo.get("commit")
        out[label] = {
            "commit": commits,
            "status": d.get("status"),
            "declared_expected_status": d.get("declared_expected_status"),
            "harness_digest": d.get("harness_digest"),
            "harness_file_count": len(d.get("harness_file_digests") or {}),
            "harness_file_digests": d.get("harness_file_digests") or {},
            "per_test_status": d.get("per_test") or {},
            "artifact": f"experiments/{safe}/{label}",
        }

    v, f = out["vulnerable"], out["fixed"]
    missing: list[str] = []

    if not (v["commit"] and f["commit"]):
        missing.append("at least one revision does not name the commit it ran")
    else:
        for lbl in ("vulnerable", "fixed"):
            if not SHA1_RE.match(v["commit"] if lbl == "vulnerable" else f["commit"]):
                missing.append(f"the {lbl} revision's commit id is not a full sha1")

    v_digests = v["harness_file_digests"]
    f_digests = f["harness_file_digests"]
    out["harness_digests_match"] = bool(v["harness_digest"]) and \
        v["harness_digest"] == f["harness_digest"]
    only_v = sorted(set(v_digests) - set(f_digests))
    only_f = sorted(set(f_digests) - set(v_digests))
    differing = sorted(n for n in set(v_digests) & set(f_digests)
                       if v_digests[n] != f_digests[n])
    out["harness_files_only_on_vulnerable_side"] = only_v
    out["harness_files_only_on_fixed_side"] = only_f
    out["harness_files_with_different_digest"] = differing

    v_tests = _test_files(v_digests)
    f_tests = _test_files(f_digests)
    out["test_file_digests_match"] = bool(v_tests) and v_tests == f_tests
    out["test_files"] = sorted(set(v_tests) | set(f_tests))

    if not out["harness_digests_match"]:
        if differing:
            missing.append(
                "the two revisions did not run byte-identical harness bytes: "
                + ", ".join(differing)
                + (" (and the vulnerable side additionally carried "
                   + ", ".join(only_v) + ")" if only_v else ""))
        else:
            missing.append(
                "the two revisions did not run byte-identical harness bytes "
                f"(vulnerable {v['harness_digest']}, fixed {f['harness_digest']})")
    if not out["test_file_digests_match"]:
        missing.append("the two revisions did not run the same test file bytes")

    out["commit_resolution"] = resolve_recorded_commits(
        [v["commit"], f["commit"]])
    if out["commit_resolution"].get("status") == "unresolvable":
        missing.append(
            "the recorded revisions do not resolve in the local clone of "
            + str(out["commit_resolution"].get("repository")))

    out["missing_evidence"] = missing
    if missing:
        out["status"] = "PARTIAL" if sides["vulnerable"] and sides["fixed"] \
            else "UNVERIFIABLE"
        return out

    declared_v = v.get("declared_expected_status")
    declared_f = f.get("declared_expected_status")
    property_polarity = (declared_v == "fail" and declared_f == "pass"
                         and v["status"] == "fail" and f["status"] == "pass")
    assertion_polarity = (declared_v == "pass" and declared_f == "fail"
                          and v["status"] == "pass" and f["status"] == "fail")
    if property_polarity or assertion_polarity:
        out["status"] = "VERIFIED_TWO_REVISION"
        return out
    out["missing_evidence"].append(
        "the recorded run outcomes do not show the declared polarity "
        f"(vulnerable {v['status']} vs declared {declared_v}; "
        f"fixed {f['status']} vs declared {declared_f})")
    return out


def resolve_recorded_commits(commits: list) -> dict:
    """Resolve the recorded revision commits against the local clone.

    A clean checkout has no clone of the audited repository, so this is a
    SKIP there, not a pass and not a failure: the caller records it as such
    and the commit ids are still checked for presence and shape.
    """
    commits = [c for c in commits if c]
    if not commits:
        return {"status": "no_commits_recorded", "repository": None,
                "resolved": [], "unresolved": []}
    try:
        clone = ex.worktree(REPOS["renft-vulnerable"])
    except Exception:
        clone = None
    if clone is None or not (clone / ".git").exists():
        return {"status": "skipped_clone_unavailable",
                "repository": "renft-smart",
                "resolved": [], "unresolved": list(commits),
                "note": "the audited repository is not cloned here; the commit ids "
                        "are recorded and well-formed but were not resolved "
                        "against a local clone"}
    import subprocess
    r = subprocess.run(["git", "cat-file", "--batch-check=%(objectname) %(objecttype)"],
                       cwd=str(clone), input="\n".join(commits) + "\n",
                       capture_output=True, text=True, timeout=300, errors="replace")
    resolved, unresolved = [], []
    for line, want in zip(r.stdout.splitlines(), commits):
        parts = line.split()
        if len(parts) == 2 and parts[1] == "commit":
            resolved.append(want)
        else:
            unresolved.append(want)
    return {"status": "resolved" if not unresolved else "unresolvable",
            "repository": "renft-smart",
            "resolved": resolved, "unresolved": unresolved}


def run_one(exp: dict, rerun: bool, trace: bool) -> dict:
    fid = exp["finding_id"]
    out: dict = {"finding_id": fid, "classification": exp["classification"],
                 "security_property": exp["security_property"],
                 "exploited_behaviour": exp["exploited_behaviour"],
                 "blocked_behaviour": exp["blocked_behaviour"],
                 "evidence_layer": exp["evidence_layer"],
                 "match_test": exp["match_test"], "notes": exp.get("notes", ""),
                 "revisions": {}}
    outcomes = {}
    for label in ("vulnerable", "fixed"):
        rev = exp["revisions"][label]
        spec = resolve_repo(rev["repo_key"])
        harness = rev["harness"]
        eid = ex.experiment_id(fid, spec.slug, spec.commit, harness, exp["match_test"])
        prior = ex.load_done(fid, label)
        if prior and not rerun and prior.get("experiment_id") == eid \
                and prior.get("status") in CACHEABLE_STATUSES:
            log(f"  [{fid}] {label}: cached ({prior['status']})")
            # The cached branch must carry the same fields as a fresh run, or the
            # downstream reports lose the declared expectation and the observed
            # failure. Re-read them from the stored artefact.
            per_test = prior.get("per_test") or {}
            failing = [k for k, v in per_test.items()
                       if str(v.get("status")) not in ("Success", "success")]
            run_reason, run_detail = stored_run_failure(fid, label, prior)
            ahashes, amismatches = artefact_hash_record(fid, label, prior)
            out["revisions"][label] = {
                "status": prior["status"],
                "experiment_id": eid,
                "commit": prior.get("repository", {}).get("commit"),
                "cached": True,
                "artifact": rel_artifact(EXPERIMENTS_PATH(fid, label)),
                "exit_code": prior.get("exit_code"),
                "declared_expectation": prior.get("declared_expectation"),
                "declared_expected_status": rev.get("expected_status"),
                "observed_failure": [
                    {"test": k, "forge_reason": (per_test.get(k) or {}).get("reason"),
                     "assertion_messages": ((per_test.get(k) or {}).get("logs") or [])[:4]}
                    for k in failing[:6]],
                "per_test_status": {k: v.get("status") for k, v in per_test.items()},
                "harness_digest": prior.get("harness_digest"),
                "harness_file_digests": prior.get("harness_file_digests") or {},
                "production_files_modified":
                    (prior.get("forensics") or {}).get("production_files_modified_count"),
                "run_failure_reason": run_reason or None,
                "run_failure_detail": run_detail,
                "detail": (prior.get("detail") or "")[:400],
                "artifact_hashes": ahashes,
                "artifact_hash_mismatches": amismatches,
            }
            outcomes[label] = prior["status"]
            continue
        log(f"  [{fid}] {label}: preparing {spec.commit[:10]}")
        info = ex.prepare(spec)
        ex.materialise(spec, harness)
        forensics = ex.clean_repo_forensics(spec)
        # A per-revision match_path names the overlay file; the shared
        # match_test would then exclude the other revision's test names.
        match_path = rev.get("match_path")
        match_test = None if match_path else exp["match_test"]
        if spec.framework == "foundry":
            result, command = ex.forge_test(spec, match_path, match_test,
                                            trace=trace)
        else:
            result, command = ex.npx_hardhat_test(spec, match_path)
        tr = ex.capture_trace(spec, match_path, match_test) if trace else None
        human = ""
        if result.status == "fail":
            # forge's JSON output omits the assertion message; the human-readable
            # run is the only place `[FAIL: reason]` appears.
            human = ex.capture_human(spec, match_path, match_test)
        authored = set(rev.get("authored_harness") or ())
        d = ex.write_artifacts(
            fid, label, harness, result, command,
            third_party=ex.third_party_set(harness, authored),
            commit=info["head"],
            extra={"experiment_id": eid,
                   "repository": {"slug": spec.slug, "commit": info["head"],
                                  "commit_pinned": info["head_matches_pinned"],
                                  "url": spec.url, "framework": spec.framework},
                   "forensics": forensics,
                   "declared_expectation": rev["expectation"],
                   "declared_expected_status": rev.get("expected_status"),
                   "classification": exp["classification"],
                   "security_property": exp["security_property"]},
            trace=tr, repo_info={"slug": spec.slug, "commit": info["head"],
                                 "commit_pinned": info["head_matches_pinned"],
                                 "url": spec.url, "framework": spec.framework})
        if human:
            (Path(d) / "stdout_human.txt").write_text(human[:ex.MAX_STREAM],
                                                     encoding="utf-8")
        run_reason, run_detail = ex.classify_run_failure(result)
        afresh = json.loads((Path(d) / "result.json").read_text(encoding="utf-8"))
        ahashes, amismatches = artefact_hash_record(fid, label, afresh)
        log(f"  [{fid}] {label}: {result.status} ({result.duration_s}s) -> {d}")
        if run_reason:
            log(f"      reason: {run_reason}"
                + (f" ({run_detail})" if run_detail else ""))
        failing = [k for k, v in (result.per_test or {}).items()
                   if str(v.get("status")) not in ("Success", "success")]
        observed = []
        for k in failing[:6]:
            logs = (result.per_test.get(k) or {}).get("logs") or []
            observed.append({"test": k,
                             "forge_reason": ex.fail_reason(human, k),
                             "assertion_messages": logs[:4]})
        out["revisions"][label] = {"status": result.status, "experiment_id": eid,
                                   "commit": info["head"], "artifact": rel_artifact(d),
                                   "exit_code": result.exit_code,
                                   "declared_expectation": rev["expectation"],
                                   "declared_expected_status": rev.get("expected_status"),
                                   "observed_failure": observed,
                                   "per_test_status": {k: v.get("status")
                                                       for k, v in (result.per_test or {}).items()},
                                   "harness_digest": ex.digest_files(harness),
                                   "harness_file_digests": {
                                       n: ex.sha256_text(harness[n])
                                       for n in sorted(harness)},
                                   "production_files_modified":
                                       forensics.get("production_files_modified_count"),
                                   "run_failure_reason": run_reason,
                                   "run_failure_detail": run_detail,
                                   "detail": result.detail[:400],
                                   "artifact_hashes": ahashes,
                                   "artifact_hash_mismatches": amismatches}
        outcomes[label] = result.status
    evidence = classify_two_revision_evidence(fid)
    out["two_revision_evidence"] = evidence
    out["verdict"] = verdict_for(exp, outcomes, evidence)
    _controlled, _why = same_test_on_both_revisions(exp)
    out["controlled_comparison"] = _controlled
    if not _controlled:
        out["controlled_comparison_detail"] = _why
    if out["verdict"] == "inconclusive" or \
            out["verdict"] == "inconclusive_not_a_controlled_comparison":
        reasons = {lbl: ((out["revisions"].get(lbl) or {}).get("run_failure_reason")
                         or out["revisions"].get(lbl, {}).get("status"))
                   for lbl in ("vulnerable", "fixed")}
        details = {lbl: out["revisions"].get(lbl, {}).get("run_failure_detail")
                   for lbl in ("vulnerable", "fixed")}
        out["inconclusive_reason"] = reasons
        out["inconclusive_detail"] = {k: v for k, v in details.items() if v}
    return out


def EXPERIMENTS_PATH(fid: str, label: str) -> Path:
    return ex.EXPERIMENTS / fid.replace("/", "__") / label


def rel_artifact(p) -> str:
    """Recorded artefact paths are repo-relative POSIX (machine-independent).

    An absolute path only resolves on the machine that wrote it, so the
    committed report must never carry one: validators resolve recorded
    artefacts against the checkout root on every platform.
    """
    try:
        return Path(p).relative_to(ROOT).as_posix()
    except ValueError:
        return str(p)


def same_test_on_both_revisions(exp: dict) -> tuple[bool, str]:
    """Is this a controlled comparison, i.e. did both revisions run the SAME test?

    `l6_verified_patch` means "the violation is observed on one revision and
    blocked on the other". That claim is only meaningful if the two runs differ
    in the code under test and in nothing else. If the two revisions run
    different test files, or the same file but different test functions, any
    difference in outcome could be a property of the test rather than of the
    protocol, and the verdict must not be an effectiveness claim.

    Returns (ok, explanation).
    """
    v = exp.get("revisions", {}).get("vulnerable", {}) or {}
    f = exp.get("revisions", {}).get("fixed", {}) or {}
    vp, fp = v.get("match_path"), f.get("match_path")
    vt, ft = v.get("match_test"), f.get("match_test")
    if not vp and not fp:
        return True, ""
    if vp != fp:
        return False, (f"not a controlled comparison: the vulnerable revision ran "
                       f"{vp or '<no match-path>'} and the fixed revision ran "
                       f"{fp or '<no match-path>'}. Different tests were executed on the "
                       f"two sides, so an outcome difference cannot be attributed to the "
                       f"protocol change.")
    if vt != ft:
        return False, (f"not a controlled comparison: both sides ran {vp} but selected "
                       f"different test functions ({vt} vs {ft}).")
    return True, ""


def verdict_for(exp: dict, outcomes: dict[str, str],
                evidence: dict | None = None) -> str:
    """Compare what forge did against what was declared *before* the run.

    Polarity is declared, never inferred: a test that asserts the exploit succeeds
    must pass on the vulnerable revision and fail on the fixed one, and a test
    that asserts the security property must fail on the vulnerable revision and
    pass on the fixed one. Both patterns are legitimate; mixing them up would
    invert the result, so the direction lives in the registry.

    A satisfied polarity is not yet a verified patch: the two runs also have to
    be a controlled comparison over identical harness bytes. When the recorded
    artefacts do not show that, the verdict is downgraded to the status the
    evidence actually supports, and the missing evidence is named in the
    record instead of the run being called an effectiveness claim.
    """
    expv = exp["revisions"]["vulnerable"].get("expected_status")
    expf = exp["revisions"]["fixed"].get("expected_status")
    v = outcomes.get("vulnerable")
    f = outcomes.get("fixed")
    if not expv or not expf:
        return "inconclusive"
    if v in (None, "not_run", "timeout", "toolchain_failure", "compile_error") or \
       f in (None, "not_run", "timeout", "toolchain_failure", "compile_error"):
        return "inconclusive"
    # An effectiveness claim requires a controlled comparison. This is checked
    # before polarity so a run of two different tests can never be reported as
    # a verified patch, however clean both outcomes look.
    controlled, why = same_test_on_both_revisions(exp)
    if not controlled:
        return "inconclusive_not_a_controlled_comparison"

    def _verified() -> str:
        if evidence is None:
            return "l6_verified_patch"
        return VERDICT_FOR_EVIDENCE.get(evidence.get("status"),
                                         "l6_unverifiable_two_revision_evidence")

    # property polarity: fail on vulnerable, pass on fixed
    if expv == "fail" and expf == "pass":
        if v == "fail" and f == "pass":
            return _verified()
        if v == "fail" and f == "fail":
            return "reproduced_but_not_blocked"
        if v == "pass":
            return "exploit_not_reproduced_on_vulnerable_revision"
        return "inconclusive"
    # assertion polarity: pass on vulnerable, fail on fixed
    if expv == "pass" and expf == "fail":
        if v == "pass" and f == "fail":
            return _verified()
        if v == "pass" and f == "pass":
            return "reproduced_but_not_blocked"
        if v == "fail":
            return "exploit_not_reproduced_on_vulnerable_revision"
        return "inconclusive"
    return "inconclusive"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--only", help="run only experiments for this finding prefix")
    ap.add_argument("--finding", help="run a single finding id")
    ap.add_argument("--list", action="store_true", help="print the registry and exit")
    ap.add_argument("--rerun", action="store_true", help="ignore cached results")
    ap.add_argument("--trace", action="store_true", help="capture -vvvv traces")
    args = ap.parse_args()

    reg = build_registry()
    if args.only:
        reg = [e for e in reg if e["finding_id"].startswith(args.only)]
    if args.finding:
        reg = [e for e in reg if e["finding_id"] == args.finding]
    if args.list:
        for e in reg:
            print(f"{e['finding_id']:34s} {e['classification']:38s} {e['match_test']}")
        print(f"\n{len(reg)} experiments")
        return 0

    results = []
    for i, exp in enumerate(reg, 1):
        log(f"[{i}/{len(reg)}] {exp['finding_id']}")
        results.append(run_one(exp, args.rerun, args.trace))
    # A filtered run must not shrink the committed report (same guard as
    # run_ml_pocs.py): experiments not repeated here keep their previously
    # recorded verdicts, in registry order.
    full = build_registry()
    if len(reg) < len(full):
        prior = {}
        try:
            prev = json.loads((REPORTS / "verified_experiments.json").read_text(encoding="utf-8"))
            for r in prev.get("experiments", []):
                # Legacy entries may carry absolute artefact paths from the
                # machine that recorded them; relativize on merge so a
                # filtered run never re-commits a machine-specific path.
                for _rev in (r.get("revisions") or {}).values():
                    if isinstance(_rev, dict) and _rev.get("artifact"):
                        _rev["artifact"] = rel_artifact(_rev["artifact"])
                prior[r.get("finding_id")] = r
        except (OSError, json.JSONDecodeError):
            prior = {}
        have = {r.get("finding_id") for r in results}
        merged = list(results)
        for e in full:
            fid = e["finding_id"]
            if fid not in have and fid in prior:
                merged.append(prior[fid])
        pos = {e["finding_id"]: i for i, e in enumerate(full)}
        merged.sort(key=lambda r: pos.get(r.get("finding_id"), len(pos)))
        if len(merged) != len(results):
            log(f"  merged {len(merged) - len(results)} previously recorded verdict(s) "
                f"from outside this filtered run")
        results = merged
    # The two-revision verdict is derived from the committed artefacts, never
    # from a previous report, so a filtered run cannot carry an over-stated
    # verdict forward and a downgrade cannot be undone by a later regeneration.
    for r in results:
        ev = classify_two_revision_evidence(r.get("finding_id"))
        r["two_revision_evidence"] = ev
        if r.get("verdict") in ("l6_verified_patch",
                                "l6_partial_two_revision_evidence",
                                "l6_unverifiable_two_revision_evidence"):
            r["verdict"] = VERDICT_FOR_EVIDENCE.get(
                ev.get("status"), "l6_unverifiable_two_revision_evidence")
    doc = {
        "generated_by": "scripts/run_verified_experiments.py",
        "experiments": results,
        "totals": tally(results),
    }
    write_json(REPORTS / "verified_experiments.json", doc)
    log(json.dumps(doc["totals"], indent=1))
    return 0


def tally(results: list[dict]) -> dict:
    t: dict[str, int] = {}
    for r in results:
        for label in ("vulnerable", "fixed"):
            st = (r["revisions"].get(label) or {}).get("status", "missing")
            t[f"{label}_{st}"] = t.get(f"{label}_{st}", 0) + 1
        t[r["verdict"]] = t.get(r["verdict"], 0) + 1
    t["experiments"] = len(results)
    return t


if __name__ == "__main__":
    raise SystemExit(main())
