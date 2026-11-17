// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Order, OfferItem, ItemType as SeaportItemType} from "@seaport-types/lib/ConsiderationStructs.sol";
import {OfferItemLib} from "@seaport-sol/SeaportSol.sol";
import {IERC1155} from "@openzeppelin-contracts/interfaces/IERC1155.sol";

import {OrderType, OrderMetadata} from "@src/libraries/RentalStructs.sol";

import {BaseTest} from "@test/BaseTest.sol";
import {SafeUtils} from "@test/utils/GnosisSafeUtils.sol";

/// Finding 2024-01-renft/M-01: a malicious lender freezes the borrower's
/// ERC-1155 balance by leaving the rental safe holding more of a rented token
/// id than was rented. The guard must allow the renter to move the unrented
/// part; a guard that blocks every transfer of a rented token id freezes it.
contract VlunRenftM01PartialTransferTest is BaseTest {
    using OfferItemLib for OfferItem;

    function test_VlunM01_NonRentedERC1155StaysTransferable() public {
        // lender owns 10 units of token id 0
        erc1155s[0].mint(address(alice.addr), 10);

        // rent 6 of them to bob
        createOrder({
            offerer: alice,
            orderType: OrderType.BASE,
            erc721Offers: 0,
            erc1155Offers: 0,
            erc20Offers: 0,
            erc721Considerations: 0,
            erc1155Considerations: 0,
            erc20Considerations: 1
        });
        withOfferItem(
            OfferItemLib
                .empty()
                .withItemType(SeaportItemType.ERC1155)
                .withToken(address(erc1155s[0]))
                .withIdentifierOrCriteria(0)
                .withStartAmount(6)
                .withEndAmount(6)
        );
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
        finalizeBaseOrderFulfillment();

        assertEq(erc1155s[0].balanceOf(address(bob.safe), 0), 6);

        // lender sends the remaining 4 units directly to the rental safe
        vm.prank(alice.addr);
        erc1155s[0].safeTransferFrom(alice.addr, address(bob.safe), 0, 4, "");
        assertEq(erc1155s[0].balanceOf(address(bob.safe), 0), 10);

        // renter moves only the 4 unrented units out of the safe
        bytes memory transferCalldata = abi.encodeWithSelector(
            IERC1155.safeTransferFrom.selector,
            address(bob.safe),
            carol.addr,
            0,
            4,
            ""
        );
        bytes memory signature = SafeUtils.signTransaction({
            safe: address(bob.safe),
            ownerPrivateKey: bob.privateKey,
            to: address(erc1155s[0]),
            transaction: transferCalldata
        });

        // SECURITY PROPERTY: the unrented part is not frozen while the rental
        // is active; the transfer must execute.
        SafeUtils.executeTransaction({
            safe: address(bob.safe),
            to: address(erc1155s[0]),
            transaction: transferCalldata,
            signature: signature
        });

        assertEq(erc1155s[0].balanceOf(address(bob.safe), 0), 6);
        assertEq(erc1155s[0].balanceOf(carol.addr, 0), 4);
    }
}
