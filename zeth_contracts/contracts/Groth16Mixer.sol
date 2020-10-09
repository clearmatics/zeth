// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.5.0;
pragma experimental ABIEncoderV2;

import "./OTSchnorrVerifier.sol";
import "./BaseMixer.sol";
import "./Groth16AltBN128.sol";

// Note that this contact is specialized for the ALT-BN128 pairing. It relies
// on the fact that scalar input elements can be stored in a single uint256.
contract Groth16Mixer is BaseMixer {

    // Structure of the verification key and proofs is opaque, determined by
    // zk-snark verification library.
    uint256[] _vk;

    constructor(
        uint256 mk_depth,
        address token,
        uint256[] memory vk)
        BaseMixer(mk_depth, token)
        public
    {
        _vk = vk;
    }

    // This function mixes coins and executes payments in zero knowledge.
    // Format of proof is internal to the zk-snark library. "input" array is
    // the set of scalar inputs to the proof. We assume that each input
    // occupies a single uint256.
    function mix(
        uint256[8] memory proof,
        uint256[4] memory vk,
        uint256 sigma,
        uint256[nbInputs] memory input,
        bytes[jsOut] memory ciphertexts)
        public payable
    {
        // 1. Check the root and the nullifiers
        bytes32[jsIn] memory nullifiers;
        check_mkroot_nullifiers_hsig_append_nullifiers_state(
            vk, input, nullifiers);

        // 2.a Verify the signature on the hash of data_to_be_signed
        bytes32 hash_to_be_signed = sha256(
            abi.encodePacked(
                uint256(msg.sender),
                // Unfortunately, we have to unroll this for now. We could
                // replace encodePacked with a custom function but this would
                // increase complexity and possibly gas usage.
                ciphertexts[0],
                ciphertexts[1],
                proof,
                input
            ));
        require(
            OTSchnorrVerifier.verify(
                vk[0], vk[1], vk[2], vk[3], sigma, hash_to_be_signed),
            "Invalid signature: Unable to verify the signature correctly"
        );

        // 2.b Verify the proof
        require(
            verifyTx(proof, input),
            "Invalid proof: Unable to verify the proof correctly"
        );

        // 3. Append the commitments to the tree
        bytes32[jsOut] memory commitments;
        assemble_commitments_and_append_to_state(input, commitments);

        // 4. Add the new root to the list of existing roots
        bytes32 new_merkle_root = recomputeRoot(jsOut);
        add_merkle_root(new_merkle_root);

        // 5. Emit the all Mix data
        emit LogMix(
            new_merkle_root,
            nullifiers,
            commitments,
            ciphertexts);

        // 6. Get the public values in Wei and modify the state depending on
        // their values
        process_public_values(input);
    }

    function verifyTx(
        uint256[8] memory proof_data,
        uint256[nbInputs] memory primaryInputs)
        internal
        returns (bool)
    {
        // For flexibility, the verifyer expects a dynamically sized array.
        // Convert the statically sized primaryInputs to a dynamic array, and
        // at the same time ensure that all inputs belong to the scalar field.

        // TODO: mechanism to pass a pointer to the fixed-size array, and
        // perform scalar check inside the zk-snark verifier.

        // Scalar field characteristic
        // solium-disable-next-line
        uint256 r = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        uint256[] memory inputValues = new uint256[](nbInputs);
        for (uint256 i = 0 ; i < nbInputs; i++) {
            require(primaryInputs[i] < r, "Input is not in scalar field");
            inputValues[i] = primaryInputs[i];
        }

        return 1 == Groth16AltBN128.verify(_vk, proof_data, inputValues);
    }
}
