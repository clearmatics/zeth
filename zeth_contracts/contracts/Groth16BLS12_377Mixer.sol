// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.5.0;
pragma experimental ABIEncoderV2;

import "./Groth16BLS12_377.sol";
import "./BLS12_377MixerBase.sol";

// Instance of BLS12_377MixerBase implementing the Groth16 verifier for the
// bls12-377 pairing.
contract Groth16BLS12_377Mixer is BLS12_377MixerBase
{
    constructor(
        uint256 mk_depth,
        address token,
        uint256[] memory vk
    )
        public
        BLS12_377MixerBase(mk_depth, token, vk)
    {
    }

    function verify_zk_proof(
        uint256[] memory proof,
        uint256[NUM_INPUTS] memory inputs
    )
        internal
        returns (bool)
    {
        // Convert the statically sized inputs to a dynamic array
        // expected by the verifyer.

        // TODO: mechanism to pass static-sized input arrays to generic
        // verifier functions to avoid this copy.

        uint256[] memory input_values = new uint256[](NUM_INPUTS);
        for (uint256 i = 0 ; i < NUM_INPUTS; i++) {
            input_values[i] = inputs[i];
        }
        return Groth16BLS12_377.verify(_vk, proof, input_values);
    }
}
