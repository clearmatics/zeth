// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
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
        uint256[] memory vk)
        BLS12_377MixerBase(mk_depth, token, vk)
        public
    {
    }

    function verify_zk_proof(
        uint256[] memory proof,
        uint256[num_inputs] memory inputs)
        internal
        returns (bool)
    {
        // Convert the statically sized inputs to a dynamic array
        // expected by the verifyer.

        // TODO: mechanism to pass static-sized input arrays to generic
        // verifier functions to avoid this copy.

        // solium-disable-next-line
        uint256[] memory input_values = new uint256[](num_inputs);
        for (uint256 i = 0 ; i < num_inputs; i++) {
            input_values[i] = inputs[i];
        }
        return Groth16BLS12_377.verify(_vk, proof, input_values);
    }
}
