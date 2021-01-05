// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.5.0;
pragma experimental ABIEncoderV2;

import "./AltBN128MixerBase.sol";


// Implementation of abstract AltBN128MixerBase contract, to allow testing
// specific methods.
contract AltBN128MixerBase_test is AltBN128MixerBase
{
    constructor(uint256 mk_depth)
        public
        AltBN128MixerBase(mk_depth, address(0), new uint256[](0))
    {
    }

    function assemble_public_values_test(uint256 residual_bits)
        public
        pure
        returns (uint256 vpub_in, uint256 vpub_out)
    {
        return assemble_public_values(residual_bits);
    }

    function assemble_hsig_test(
        uint256[NUM_INPUTS] memory primary_inputs
    )
        public
        pure
        returns(bytes32 hsig)
    {
        return assemble_hsig(primary_inputs);
    }

    function assemble_nullifier_test(
        uint256 index,
        uint256[NUM_INPUTS] memory primary_inputs
    )
        public
        pure
        returns(bytes32 nf)
    {
        return assemble_nullifier(index, primary_inputs);
    }

    // Dummy implementation of abstract function
    function verify_zk_proof(
        uint256[] memory /* proof */,
        uint256[NUM_INPUTS] memory /* inputs */
    )
        internal
        returns (bool)
    {
        return false;
    }
}
