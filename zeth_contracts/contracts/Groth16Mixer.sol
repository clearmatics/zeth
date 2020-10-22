// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.5.0;
pragma experimental ABIEncoderV2;

import "./OTSchnorrVerifier.sol";
import "./BaseMixer.sol";
import "./Groth16AltBN128.sol";

// Abstract base contract for all mixers that use Groth16 proofs. Assumes that
// scalars can be encoded in a single uint256.
contract Groth16MixerBase is BaseMixer
{
    // Implementations must provide this
    function verify_zk_proof(
        uint256[] memory proof,
        uint256[num_inputs] memory inputs)
        internal
        returns (bool);

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
        uint256[] memory proof,
        uint256[4] memory vk,
        uint256 sigma,
        uint256[num_inputs] memory inputs,
        bytes[jsOut] memory ciphertexts)
        public payable
    {
        // 1. Check the root and the nullifiers
        bytes32[jsIn] memory nullifiers;
        check_mkroot_nullifiers_hsig_append_nullifiers_state(
            vk, inputs, nullifiers);

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
                inputs
            ));
        require(
            OTSchnorrVerifier.verify(
                vk[0], vk[1], vk[2], vk[3], sigma, hash_to_be_signed),
            "Invalid signature: Unable to verify the signature correctly"
        );

        // 2.b Verify the proof
        require(
            verify_zk_proof(proof, inputs),
            "Invalid proof: Unable to verify the proof correctly"
        );

        // 3. Append the commitments to the tree
        bytes32[jsOut] memory commitments;
        assemble_commitments_and_append_to_state(inputs, commitments);

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
        process_public_values(inputs);
    }
}

contract Groth16Mixer is Groth16MixerBase
{
    // Constants regarding the hash digest length, the prime number used and
    // its associated length in bits and the max values (v_in and v_out)
    // field_capacity = floor( log_2(r) )
    uint256 constant field_capacity = 253;

    // Number of residual bits per bytes32
    uint256 constant num_residual_bits = digest_length - field_capacity;

    // Shift to move residual bits from lowest order to highest order
    uint256 constant residual_bits_shift = 256 - num_residual_bits;

    // Mask to extract the residual bits in the high-order position
    uint256 constant residual_bits_mask =
    ((1 << num_residual_bits) - 1) << residual_bits_shift;

    // Total number of residual bits from packing of 256-bit long string into
    // 253-bit long field elements to which are added the public value of size
    // 64 bits
    uint256 constant total_num_residual_bits =
    2 * public_value_bits + num_residual_bits * num_hash_digests;

    constructor(
        uint256 mk_depth,
        address token,
        uint256[] memory vk)
        Groth16MixerBase(mk_depth, token, vk)
        public
    {
    }

    // Utility function to extract a full uint256 from a field element and the
    // n-th set of residual bits from `residual`.
    function extract_bytes32(
        uint256 field_element, uint256 residual, uint256 residual_bits_set_idx)
        internal pure
        returns(bytes32)
    {
        // The residual bits are located at:
        //   (2 * public_value_bits) + (residual_bits_set_idx*num_residual_bits)
        //
        // Shift to occupy the highest order bits:
        // 255                                       128         64           0
        //  | bits_to_shift |     | residual_bits_idx |           |           |
        //  | <------------ | xxx |                   |<v_pub_in>)|<v_pub_out>|
        //                residual bits

        // Number of bits AFTER public values
        uint256 residual_bits_idx = residual_bits_set_idx * num_residual_bits;
        uint256 bits_to_shift =
        residual_bits_shift - total_public_value_bits - residual_bits_idx;
        uint256 residual_bits = (residual << bits_to_shift) & residual_bits_mask;
        return bytes32(field_element | residual_bits);
    }

    function verify_zk_proof(
        uint256[] memory proof,
        uint256[num_inputs] memory inputs)
        internal
        returns (bool)
    {
        // Convert the statically sized primaryInputs to a dynamic array
        // expected by the verifyer.

        // TODO: mechanism to pass static-sized input arrays to generic
        // verifier functions to avoid this copy.

        // solium-disable-next-line
        uint256[] memory input_values = new uint256[](num_inputs);
        for (uint256 i = 0 ; i < num_inputs; i++) {
            input_values[i] = inputs[i];
        }
        return Groth16AltBN128.verify(_vk, proof, input_values);
    }
}
