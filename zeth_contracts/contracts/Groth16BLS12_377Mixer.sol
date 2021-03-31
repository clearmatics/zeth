// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.8.0;

import "./Groth16BLS12_377.sol";
import "./BLS12_377MixerBase.sol";

// Instance of BLS12_377MixerBase implementing the Groth16 verifier for the
// bls12-377 pairing.
contract Groth16BLS12_377Mixer is BLS12_377MixerBase
{
    constructor(
        uint256 mk_depth,
        address token,
        uint256[] memory vk,
        address permitted_dispatcher,
        uint256[2] memory vk_hash
    )
        BLS12_377MixerBase(mk_depth, token, vk, permitted_dispatcher, vk_hash)
    {
    }

    function verifyZkProof(
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
        return Groth16BLS12_377.verify(_vk, proof, input_values);
    }
}
