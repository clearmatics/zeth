// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.8.0;

import "./AbstractMixerAltBN128.sol";


// Implementation of AbstractMixerAltBN128 contract, to allow testing
// specific methods.
contract TestAbstractMixerAltBN128 is AbstractMixerAltBN128
{
    constructor(
        uint256 mkDepth,
        address permittedDispatcher,
        uint256[2] memory vkHash
    )
        AbstractMixerAltBN128(
            mkDepth,
            address(0),
            new uint256[](0),
            permittedDispatcher,
            vkHash)
    {
    }

    function testHashPublicProofData(
        uint256[_NUM_INPUTS] memory publicData
    )
        external
        returns (uint256)
    {
        return _hashPublicProofData(publicData);
    }

    function testAssemblePublicValues(uint256 residualBits)
        external
        pure
        returns (uint256 vpub_in, uint256 vpub_out)
    {
        return _assemblePublicValues(residualBits);
    }

    function testAssembleHsig(
        uint256[_NUM_INPUTS] memory primaryInputs
    )
        external
        pure
        returns(bytes32 hsig)
    {
        return _assembleHsig(primaryInputs);
    }

    function testAssembleNullifier(
        uint256 index,
        uint256[_NUM_INPUTS] memory primaryInputs
    )
        external
        pure
        returns(bytes32 nf)
    {
        return _assembleNullifier(index, primaryInputs);
    }

    // Dummy implementation of abstract function
    function _verifyZkProof(
        uint256[] memory /* proof */,
        uint256 /* publicInputsHash */
    )
        internal
        pure
        override
        returns (bool)
    {
        return false;
    }
}
