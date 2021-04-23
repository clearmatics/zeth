// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.8.0;

import "./BaseMixerAltBN128.sol";
import "./LGroth16AltBN128.sol";

/// Instance of BaseMixerAltBN128 implementing the Groth16 verifier for the
/// alt-bn128 pairing.
contract MixerGroth16AltBN128 is BaseMixerAltBN128
{
    constructor(
        uint256 mkDepth,
        address token,
        uint256[] memory vk,
        address permittedDispatcher,
        uint256[2] memory vkHash
    )
        BaseMixerAltBN128(mkDepth, token, vk, permittedDispatcher, vkHash)
    {
    }

    function _verifyZkProof(
        uint256[] memory proof,
        uint256 publicInputsHash
    )
        internal
        override
        returns (bool)
    {
        // Convert the single primary input to a dynamic array
        // expected by the verifier.
        uint256[] memory inputValues = new uint256[](1);
        inputValues[0] = publicInputsHash;
        return LGroth16AltBN128._verify(_vk, proof, inputValues);
    }
}