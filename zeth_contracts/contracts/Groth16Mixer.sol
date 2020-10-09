// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.5.0;
pragma experimental ABIEncoderV2;

import "./OTSchnorrVerifier.sol";
import "./BaseMixer.sol";
import "./Groth16AltBN128.sol";

// Note that this contact is specialized for the ALT-BN128 pairing. It relies
// on the fact that scalar input elements can be stored in a single uint256_t.
contract Groth16Mixer is BaseMixer {

    // Format of the verification key and proofs is determined by
    // alt_bn128_groth16 library.
    Groth16AltBN128.VerifyingKey verifyKey;

    constructor(
        uint256 mk_depth,
        address token,
        uint256[] memory vk)
        BaseMixer(mk_depth, token)
        public
    {
        // TODO: move all this logic into alt_bn128_groth16 library.

        uint256 vk_words = vk.length;
        require(vk_words >= 12, "invalid vk length");


        verifyKey.Alpha = Pairing.G1Point(vk[0], vk[1]);
        verifyKey.Minus_Beta = Pairing.G2Point(vk[2], vk[3], vk[4], vk[5]);
        verifyKey.Minus_Delta = Pairing.G2Point(vk[6], vk[7], vk[8], vk[9]);

        // The `ABC` are elements of G1 (and thus have 2 coordinates in the
        // underlying field). Here, we reconstruct these group elements from
        // field elements (ABC_coords are field elements)
        for (uint256 i = 10 ; i < vk_words ; i += 2) {
            verifyKey.ABC.push(Pairing.G1Point(vk[i], vk[i + 1]));
        }
    }

    function mix(
        uint256[8] memory proof,
        uint256[4] memory vk,
        uint256 sigma,
        uint256[nbInputs] memory input,
        bytes[jsOut] memory ciphertexts)
        public payable {

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
        returns (bool) {
        // TODO: move this logic into the alt_bn128_groth16 library.

        // Scalar field characteristic
        // solium-disable-next-line
        uint256 r = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

        // Make sure that all primary inputs lie in the scalar field

        // TODO: update `verify` method to handle static arrays and pass
        // `primaryInputs` directly.
        uint256[] memory inputValues = new uint256[](nbInputs);
        for (uint256 i = 0 ; i < nbInputs; i++) {
            require(primaryInputs[i] < r, "Input is not in scalar field");
            inputValues[i] = primaryInputs[i];
        }

        return 1 == Groth16AltBN128.verify(verifyKey, inputValues, proof_data);
    }
}
