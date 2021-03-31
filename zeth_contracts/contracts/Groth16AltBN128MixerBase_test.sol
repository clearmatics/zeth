// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.8.0;

import "./Groth16AltBN128Mixer.sol";


// Implementation of Groth16AltBN128MixerBase contract, to allow testing
// specific methods.
contract Groth16AltBN128MixerBase_test is Groth16AltBN128Mixer
{
    constructor(
        uint256 mk_depth,
        address permitted_dispatcher,
        uint256[2] memory vk_hash
    )
        Groth16AltBN128Mixer(
            mk_depth,
            address(0),
            new uint256[](0),
            permitted_dispatcher,
            vk_hash)
    {
    }

    function hash_public_proof_data_test(
        uint256[NUM_INPUTS] memory public_data
    )
        public
        returns (uint256)
    {
        return hashPublicProofData(public_data);
    }

    function assemble_public_values_test(uint256 residualBits)
        public
        pure
        returns (uint256 vpub_in, uint256 vpub_out)
    {
        return assemblePublicValues(residualBits);
    }

    function assemble_hsig_test(
        uint256[NUM_INPUTS] memory primaryInputs
    )
        public
        pure
        returns(bytes32 hsig)
    {
        return assembleHsig(primaryInputs);
    }

    function assemble_nullifier_test(
        uint256 index,
        uint256[NUM_INPUTS] memory primaryInputs
    )
        public
        pure
        returns(bytes32 nf)
    {
        return assembleNullifier(index, primaryInputs);
    }

    // Dummy implementation of abstract function
    function verifyZkProof(
        uint256[] memory /* proof */,
        uint256[NUM_INPUTS] memory /* inputs */
    )
        internal
        returns (bool)
    {
        return false;
    }
}
