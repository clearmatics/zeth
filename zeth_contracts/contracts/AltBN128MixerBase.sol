// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.5.0;
pragma experimental ABIEncoderV2;

import "./MixerBase.sol";
import "./MiMC7.sol";

// Partial implementation of abstract MixerBase which implements the
// curve-specific methods to use the ALT-BN128 pairing.
contract AltBN128MixerBase is MixerBase
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
        MixerBase(mk_depth, token, vk)
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

    // Use MiMC7 as the Merkle tree hash function.
    function hash(bytes32 left, bytes32 right) internal returns(bytes32)
    {
        return MiMC7.hash(left, right);
    }
}
