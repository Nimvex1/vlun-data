// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Order, OfferItem, ItemType as SeaportItemType} from "@seaport-types/lib/ConsiderationStructs.sol";
import {OfferItemLib} from "@seaport-sol/SeaportSol.sol";
import {ERC721Burnable} from "@openzeppelin-contracts/token/ERC721/extensions/ERC721Burnable.sol";

import {OrderType, OrderMetadata} from "@src/libraries/RentalStructs.sol";
import {Errors} from "@src/libraries/Errors.sol";

import {BaseTest} from "@test/BaseTest.sol";
import {SafeUtils} from "@test/utils/GnosisSafeUtils.sol";

/// Finding 2024-01-renft/M-08: an asset held by a rental safe can be destroyed
/// while the rental is active. The guard must reject a burn selector.
contract VlunRenftM08DestructiveBurnTest is BaseTest {
    using OfferItemLib for OfferItem;

    function test_VlunM08_RentedERC721CannotBeBurned() public {
        // lender mints token id 0 and rents it to bob
        erc721s[0].mint(address(alice.addr));

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
                .withItemType(SeaportItemType.ERC721)
                .withToken(address(erc721s[0]))
                .withIdentifierOrCriteria(0)
                .withStartAmount(1)
                .withEndAmount(1)
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

        assertEq(erc721s[0].ownerOf(0), address(bob.safe));

        bytes memory burnCalldata = abi.encodeWithSelector(
            ERC721Burnable.burn.selector,
            0
        );
        bytes memory signature = SafeUtils.signTransaction({
            safe: address(bob.safe),
            ownerPrivateKey: bob.privateKey,
            to: address(erc721s[0]),
            transaction: burnCalldata
        });

        // SECURITY PROPERTY: the guard rejects the destructive call while the
        // asset is rented.
        SafeUtils.executeTransactionWithError({
            safe: address(bob.safe),
            to: address(erc721s[0]),
            transaction: burnCalldata,
            signature: signature,
            expectedError: abi.encodeWithSelector(
                Errors.GuardPolicy_UnauthorizedSelector.selector,
                ERC721Burnable.burn.selector
            )
        });

        assertEq(erc721s[0].ownerOf(0), address(bob.safe));
    }
}
