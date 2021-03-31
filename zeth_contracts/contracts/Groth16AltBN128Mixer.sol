// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.8.0;

import "./AltBN128MixerBase.sol";
import "./Groth16AltBN128.sol";

/// Instance of AltBN128MixerBase implementing the Groth16 verifier for the
/// alt-bn128 pairing.
contract Groth16AltBN128Mixer is AltBN128MixerBase
{
    constructor(
        uint256 mk_depth,
        address token,
        uint256[] memory vk,
        address permitted_dispatcher,
        uint256[2] memory vk_hash
    )
        AltBN128MixerBase(mk_depth, token, vk, permitted_dispatcher, vk_hash)
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
        return Groth16AltBN128.verify(_vk, proof, input_values);
    }
}
