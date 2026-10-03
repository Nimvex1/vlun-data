// SPDX-License-Identifier: BUSL-1.1
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
