// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.8.0;

import "./LGroth16BLS12_377.sol";
import "./BaseMixerBLS12_377.sol";

// Instance of BaseMixerBLS12_377 implementing the Groth16 verifier for the
// bls12-377 pairing.
contract MixerGroth16BLS12_377 is BaseMixerBLS12_377
{
    constructor(
        uint256 mkDepth,
        address token,
        uint256[] memory vk,
        address permittedDispatcher,
        uint256[2] memory vkHash
    )
        BaseMixerBLS12_377(mkDepth, token, vk, permittedDispatcher, vkHash)
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
        uint256[] memory input_values = new uint256[](1);
        input_values[0] = publicInputsHash;
        return LGroth16BLS12_377._verify(_vk, proof, input_values);
    }
}
