// Evidence harness for the M-01 two-side PoC (item 8, VLUN V3.1 patch candidates).
//
// Adapted from test/FeeTaker.js of 1inch/limit-order-protocol at the fix
// revision 8c19fb95792c8fec76ed8f11554300dc0056416d (repository MIT-licensed;
// see its LICENSE.md at either pinned revision). Adaptation for the audited
// revision 198a6d719aef8b6cd0b29e18a128f4abcf978046: parameterless FeeTaker
// constructor and the uint24/1e7 extraData fee encoding of that revision.
// One test is added back to that revision's suite: the M-01 scenario
// (makerTraits.unwrapWeth + postInteraction fee) with the fixed revision's
// expected outcome. Run from the revision's worktree:
//
//     npx hardhat test test/FeeTaker.js
//
// Expected: vulnerable revision -> 4 passing, 1 failing (the transaction
// reverts in OrderMixin._fill); fixed revision -> 6 passing.
const hre = require('hardhat');
const { ethers } = hre;
const { expect } = require('@1inch/solidity-utils');
const { loadFixture } = require('@nomicfoundation/hardhat-network-helpers');
const { deploySwapTokens } = require('./helpers/fixtures');
const { buildOrder, buildTakerTraits, signOrder, buildMakerTraits } = require('./helpers/orderUtils');
const { ether, trim0x } = require('./helpers/utils');

describe('FeeTaker', function () {
    let addr, addr1, addr2, addr3;
    before(async function () {
        [addr, addr1, addr2, addr3] = await ethers.getSigners();
    });

    async function deployContractsAndInit () {
        const { dai, weth, inch, swap, chainId } = await deploySwapTokens();

        await dai.mint(addr, ether('1000000'));
        await weth.deposit({ value: ether('100') });
        await inch.mint(addr, ether('1000000'));
        await dai.mint(addr1, ether('1000000'));
        await weth.connect(addr1).deposit({ value: ether('100') });
        await inch.mint(addr1, ether('1000000'));

        await dai.approve(swap, ether('1000000'));
        await weth.approve(swap, ether('1000000'));
        await inch.approve(swap, ether('1000000'));
        await dai.connect(addr1).approve(swap, ether('1000000'));
        await weth.connect(addr1).approve(swap, ether('1000000'));
        await inch.connect(addr1).approve(swap, ether('1000000'));

        const FeeTaker = await ethers.getContractFactory('FeeTaker');
        const feeTaker = await FeeTaker.deploy();

        return { dai, weth, inch, swap, chainId, feeTaker };
    };

    it('should send all tokens to the maker with 0 fee', async function () {
        const { dai, weth, swap, chainId, feeTaker } = await loadFixture(deployContractsAndInit);

        const makingAmount = ether('300');
        const takingAmount = ether('0.3');
        const fee = 0;
        const feeRecipient = addr2.address;

        const order = buildOrder(
            {
                maker: addr1.address,
                receiver: await feeTaker.getAddress(),
                makerAsset: await dai.getAddress(),
                takerAsset: await weth.getAddress(),
                makingAmount,
                takingAmount,
            },
            {
                postInteraction: await feeTaker.getAddress() + trim0x(ethers.solidityPacked(['uint24', 'address'], [fee, feeRecipient])),
            },
        );

        const { r, yParityAndS: vs } = ethers.Signature.from(await signOrder(order, chainId, await swap.getAddress(), addr1));
        const takerTraits = buildTakerTraits({
            extension: order.extension,
        });
        const fillTx = swap.fillOrderArgs(order, r, vs, makingAmount, takerTraits.traits, takerTraits.args);
        await expect(fillTx).to.changeTokenBalances(dai, [addr, addr1], [makingAmount, -makingAmount]);
        await expect(fillTx).to.changeTokenBalances(weth, [addr, addr1, addr2], [-takingAmount, takingAmount, 0]);
    });

    it('should send all tokens to the maker receiver with 0 fee', async function () {
        const { dai, weth, swap, chainId, feeTaker } = await loadFixture(deployContractsAndInit);

        const makingAmount = ether('300');
        const takingAmount = ether('0.3');
        const fee = 0;
        const feeRecipient = addr2.address;
        const makerReceiver = addr3.address;

        const order = buildOrder(
            {
                maker: addr1.address,
                receiver: await feeTaker.getAddress(),
                makerAsset: await dai.getAddress(),
                takerAsset: await weth.getAddress(),
                makingAmount,
                takingAmount,
            },
            {
                postInteraction: await feeTaker.getAddress() +
                    trim0x(ethers.solidityPacked(['uint24', 'address', 'address'], [fee, feeRecipient, makerReceiver])),
            },
        );

        const { r, yParityAndS: vs } = ethers.Signature.from(await signOrder(order, chainId, await swap.getAddress(), addr1));
        const takerTraits = buildTakerTraits({
            extension: order.extension,
        });
        const fillTx = swap.fillOrderArgs(order, r, vs, makingAmount, takerTraits.traits, takerTraits.args);
        await expect(fillTx).to.changeTokenBalances(dai, [addr, addr1], [makingAmount, -makingAmount]);
        await expect(fillTx).to.changeTokenBalances(weth, [addr, addr1, addr2, addr3], [-takingAmount, 0, 0, takingAmount]);
    });

    it('should charge fee', async function () {
        const { dai, weth, swap, chainId, feeTaker } = await loadFixture(deployContractsAndInit);

        const makingAmount = ether('300');
        const takingAmount = ether('0.3');
        const fee = BigInt(1e6);
        const feeCalculated = takingAmount * fee / BigInt(1e7);
        const feeRecipient = addr2.address;

        const order = buildOrder(
            {
                maker: addr1.address,
                receiver: await feeTaker.getAddress(),
                makerAsset: await dai.getAddress(),
                takerAsset: await weth.getAddress(),
                makingAmount,
                takingAmount,
            },
            {
                postInteraction: await feeTaker.getAddress() + trim0x(ethers.solidityPacked(['uint24', 'address'], [fee, feeRecipient])),
            },
        );

        const { r, yParityAndS: vs } = ethers.Signature.from(await signOrder(order, chainId, await swap.getAddress(), addr1));
        const takerTraits = buildTakerTraits({
            extension: order.extension,
        });
        const fillTx = swap.fillOrderArgs(order, r, vs, makingAmount, takerTraits.traits, takerTraits.args);
        await expect(fillTx).to.changeTokenBalances(dai, [addr, addr1], [makingAmount, -makingAmount]);
        await expect(fillTx).to.changeTokenBalances(weth, [addr, addr1, addr2], [-takingAmount, takingAmount - feeCalculated, feeCalculated]);
    });

    it('should charge fee and send the rest to the maker receiver', async function () {
        const { dai, weth, swap, chainId, feeTaker } = await loadFixture(deployContractsAndInit);

        const makingAmount = ether('300');
        const takingAmount = ether('0.3');
        const fee = BigInt(1e6);
        const feeCalculated = takingAmount * fee / BigInt(1e7);
        const feeRecipient = addr2.address;
        const makerReceiver = addr3.address;

        const order = buildOrder(
            {
                maker: addr1.address,
                receiver: await feeTaker.getAddress(),
                makerAsset: await dai.getAddress(),
                takerAsset: await weth.getAddress(),
                makingAmount,
                takingAmount,
            },
            {
                postInteraction: await feeTaker.getAddress() +
                    trim0x(ethers.solidityPacked(['uint24', 'address', 'address'], [fee, feeRecipient, makerReceiver])),
            },
        );

        const { r, yParityAndS: vs } = ethers.Signature.from(await signOrder(order, chainId, await swap.getAddress(), addr1));
        const takerTraits = buildTakerTraits({
            extension: order.extension,
        });
        const fillTx = swap.fillOrderArgs(order, r, vs, makingAmount, takerTraits.traits, takerTraits.args);
        await expect(fillTx).to.changeTokenBalances(dai, [addr, addr1], [makingAmount, -makingAmount]);
        await expect(fillTx).to.changeTokenBalances(weth, [addr, addr1, addr2, addr3], [-takingAmount, 0, feeCalculated, takingAmount - feeCalculated]);
    });

    it('M-01 PoC: should charge fee in eth (fixed-revision expectation adapted to the vulnerable interface)', async function () {
        const { dai, weth, swap, chainId, feeTaker } = await loadFixture(deployContractsAndInit);

        const makingAmount = ether('300');
        const takingAmount = ether('0.3');
        const fee = BigInt(1e6);
        const feeCalculated = takingAmount * fee / BigInt(1e7);
        const feeRecipient = addr2.address;

        const order = buildOrder(
            {
                maker: addr1.address,
                receiver: await feeTaker.getAddress(),
                makerAsset: await dai.getAddress(),
                takerAsset: await weth.getAddress(),
                makingAmount,
                takingAmount,
                makerTraits: buildMakerTraits({ unwrapWeth: true }),
            },
            {
                postInteraction: await feeTaker.getAddress() + trim0x(ethers.solidityPacked(['uint24', 'address'], [fee, feeRecipient])),
            },
        );

        const { r, yParityAndS: vs } = ethers.Signature.from(await signOrder(order, chainId, await swap.getAddress(), addr1));
        const takerTraits = buildTakerTraits({
            extension: order.extension,
        });
        const fillTx = swap.fillOrderArgs(order, r, vs, makingAmount, takerTraits.traits, takerTraits.args);
        await expect(fillTx).to.changeTokenBalances(dai, [addr, addr1], [makingAmount, -makingAmount]);
        await expect(fillTx).to.changeTokenBalance(weth, addr, -takingAmount);
        await expect(fillTx).to.changeEtherBalances([addr1, addr2], [takingAmount - feeCalculated, feeCalculated]);
    });
});
