// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.5.0;
pragma experimental ABIEncoderV2;

import "./MixerBase.sol";
import "./MiMC31.sol";

/// Partial implementation of abstract MixerBase which implements the
/// curve-specific methods to use the BLS12-377 pairing.
contract BLS12_377MixerBase is MixerBase
{
    // TODO: Code here is very similar to AltBN128MixerBase, with only the
    // constants changed. Look into sharing more code (possibly by making some
    // of these constants dynamic).

    // Constants regarding the hash digest length, the prime number used and
    // its associated length in bits and the max values (v_in and v_out)

    // Number of bits that can be reliably represented by a single field
    // element:
    //   FIELD_CAPACITY = floor( log_2(r) )
    // Denoted FIELDCAP in Zeth specifications.
    uint256 internal constant FIELD_CAPACITY = 252;

    // Number of residual bits per bytes32
    uint256 internal constant NUM_RESIDUAL_BITS =
        DIGEST_LENGTH - FIELD_CAPACITY;

    // Shift to move residual bits from lowest order to highest order
    uint256 internal constant RESIDUAL_BITS_SHIFT = 256 - NUM_RESIDUAL_BITS;

    // Mask to extract the residual bits in the high-order position
    uint256 internal constant RESIDUAL_BITS_MASK =
        ((1 << NUM_RESIDUAL_BITS) - 1) << RESIDUAL_BITS_SHIFT;

    // Total number of bits required to hold all residual bits from, including
    // the public vin and vout values (each 64 bits long). Denoted RSDBLEN in
    // Zeth specifications.
    uint256 internal constant RESIDUAL_BITS_LENGTH =
        2 * PUBLIC_VALUE_BITS + NUM_RESIDUAL_BITS * NUM_HASH_DIGESTS;

    constructor(
        uint256 mk_depth,
        address token,
        uint256[] memory vk
    )
        public
        MixerBase(mk_depth, token, vk)
    {
    }

    function hash(bytes32 left, bytes32 right) internal returns(bytes32) {
        return MiMC31.hash(left, right);
    }

    /// Extract a full uint256 from a field element and the n-th set of
    /// residual bits from `residual`.
    function extract_bytes32(
        uint256 field_element,
        uint256 residual,
        uint256 residual_bits_set_idx
    )
        internal
        pure
        returns(bytes32)
    {
        // The residual_bits_set_idx-th set of residual bits (denoted r_i
        // below) start at bit:
        //   (2*PUBLIC_VALUE_BITS) + (residual_bits_set_idx*num_residual_bits)
        //
        // Shift r_i to occupy the highest order bits:
        // 255                                       128        64           0
        //  | bits_to_shift |     | residual_bits_idx |          |           |
        //  | <------------ |<r_i>|                   |<v_pub_in>|<v_pub_out>|

        // Number of bits AFTER public values
        uint256 residual_bits_idx = residual_bits_set_idx * NUM_RESIDUAL_BITS;
        uint256 bits_to_shift =
        RESIDUAL_BITS_SHIFT - TOTAL_PUBLIC_VALUE_BITS - residual_bits_idx;
        uint256 residual_bits =
            (residual << bits_to_shift) & RESIDUAL_BITS_MASK;
        return bytes32(field_element | residual_bits);
    }
}
