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
from vlun import REPORTS, log, write_json  # noqa: E402

# ---------------------------------------------------------------------------
# repositories
# ---------------------------------------------------------------------------
RENFT_VULN = "3ddd32455a849c3c6dc3c3aad7a33a6c9b44c291"   # audited snapshot
RENFT_URL = "https://github.com/re-nft/smart-contracts.git"

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
    """Point `@test/<p>` imports at the overlay copy when we supply one."""
    out = text
    for original, flat in sorted(overlay_paths.items()):
        out = out.replace(f'@test/{original}', f'@test/vlun_poc/{flat}')
        out = out.replace(f'"{original}"', f'"@test/vlun_poc/{flat}"')
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
        overlays=["mocks/tokens/weird/MockAlwaysRevertERC20.sol"],
        match_test="test_VlunMaliciousSeaportTip",
        custom="h01_tip",
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
        overlays=["utils/GnosisSafeUtils.sol",
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
        overlays=["utils/GnosisSafeUtils.sol",
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
        for path in case["overlays"]:
            rev = RENFT_FIXTURE_UPDATES.get(path, case["fix_commit"])
            overlay_files[path] = git_show("renft-vulnerable", rev, "test/" + path)
        if case.get("custom") == "h01_tip":
            # The published regression test asserts an error selector introduced by
            # the fix, so it cannot compile on the audited revision. The
            # reconstruction keeps the attack sequence and asserts the property.
            fixed_harness = build_harness(
                {case["test"]: git_show("renft-vulnerable", case["fix_commit"],
                                        "test/" + case["test"])}, overlay_files)
            vuln_harness = build_harness(
                {"VlunMaliciousSeaportTip.t.sol": H01_SOURCE}, overlay_files)
            vuln_match_path = "test/vlun_poc/VlunMaliciousSeaportTip.t.sol"
            fixed_match_path = ("test/vlun_poc/"
                                + flatten(case["test"]))
        else:
            test_src = git_show("renft-vulnerable", case["fix_commit"],
                                "test/" + case["test"])
            base = {case["test"]: test_src}
            vuln_harness = build_harness(base, overlay_files)
            fixed_harness = dict(vuln_harness)
        if vuln_match_path is None:
            vuln_match_path = "test/vlun_poc/" + flatten(case["test"])
        if fixed_match_path is None:
            fixed_match_path = vuln_match_path
        reg.append({
            "finding_id": case["finding_id"],
            "classification": case["classification"],
            "security_property": case["security_property"],
            "exploited_behaviour": case["exploited"],
            "blocked_behaviour": case["blocked"],
            "evidence_layer": "dynamic_poc_plus_source_diff",
            "notes": ("the regression test shipped by the mitigation commit is executed "
                      "against both revisions; fixture files it needs are supplied as an "
                      "overlay so no repository file is modified"),
            "match_test": case["match_test"],
            "revisions": {
                "vulnerable": {"repo_key": "renft-vulnerable",
                               "harness": vuln_harness,
                               "match_path": vuln_match_path,
                               "authored_harness": ["VlunMaliciousSeaportTip.t.sol"],
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
                and prior.get("status") in ("pass", "fail"):
            log(f"  [{fid}] {label}: cached ({prior['status']})")
            # The cached branch must carry the same fields as a fresh run, or the
            # downstream reports lose the declared expectation and the observed
            # failure. Re-read them from the stored artefact.
            per_test = prior.get("per_test") or {}
            failing = [k for k, v in per_test.items()
                       if str(v.get("status")) not in ("Success", "success")]
            out["revisions"][label] = {
                "status": prior["status"],
                "experiment_id": eid,
                "commit": prior.get("repository", {}).get("commit"),
                "cached": True,
                "artifact": str(EXPERIMENTS_PATH(fid, label)),
                "exit_code": prior.get("exit_code"),
                "declared_expectation": prior.get("declared_expectation"),
                "declared_expected_status": rev.get("expected_status"),
                "observed_failure": [
                    {"test": k, "forge_reason": (per_test.get(k) or {}).get("reason"),
                     "assertion_messages": ((per_test.get(k) or {}).get("logs") or [])[:4]}
                    for k in failing[:6]],
                "per_test_status": {k: v.get("status") for k, v in per_test.items()},
                "production_files_modified":
                    (prior.get("forensics") or {}).get("production_files_modified_count"),
                "run_failure_reason": None,
                "run_failure_detail": None,
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
                                   "commit": info["head"], "artifact": str(d),
                                   "exit_code": result.exit_code,
                                   "declared_expectation": rev["expectation"],
                                   "declared_expected_status": rev.get("expected_status"),
                                   "observed_failure": observed,
                                   "per_test_status": {k: v.get("status")
                                                       for k, v in (result.per_test or {}).items()},
                                   "production_files_modified":
                                       forensics.get("production_files_modified_count"),
                                   "run_failure_reason": run_reason,
                                   "run_failure_detail": run_detail,
                                   "detail": result.detail[:400]}
        outcomes[label] = result.status
    out["verdict"] = verdict_for(exp, outcomes)
    if out["verdict"] == "inconclusive":
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


def verdict_for(exp: dict, outcomes: dict[str, str]) -> str:
    """Compare what forge did against what was declared *before* the run.

    Polarity is declared, never inferred: a test that asserts the exploit succeeds
    must pass on the vulnerable revision and fail on the fixed one, and a test
    that asserts the security property must fail on the vulnerable revision and
    pass on the fixed one. Both patterns are legitimate; mixing them up would
    invert the result, so the direction lives in the registry.
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
    # property polarity: fail on vulnerable, pass on fixed
    if expv == "fail" and expf == "pass":
        if v == "fail" and f == "pass":
            return "l6_verified_patch"
        if v == "fail" and f == "fail":
            return "reproduced_but_not_blocked"
        if v == "pass":
            return "exploit_not_reproduced_on_vulnerable_revision"
        return "inconclusive"
    # assertion polarity: pass on vulnerable, fail on fixed
    if expv == "pass" and expf == "fail":
        if v == "pass" and f == "fail":
            return "l6_verified_patch"
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
