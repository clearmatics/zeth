// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.8.0;

import "./MixerBase.sol";
import "./MiMC31.sol";

/// Partial implementation of abstract MixerBase which implements the
/// curve-specific methods to use the BLS12-377 pairing.
abstract contract BLS12_377MixerBase is MixerBase
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
        uint256[] memory vk,
        address permitted_dispatcher,
        uint256[2] memory vk_hash
    )
        MixerBase(mk_depth, token, vk, permitted_dispatcher, vk_hash)
    {
    }

    function hash(bytes32 left, bytes32 right)
        internal
        pure
        override
        returns(bytes32)
    {
        return MiMC31.hash(left, right);
    }

    /// Extract a full uint256 from a field element and the n-th set of
    /// residual bits from `residual`.
    function extractBytes32(
        uint256 fieldElement,
        uint256 residual,
        uint256 residualBitsSetIdx
    )
        internal
        pure
        override
        returns(bytes32)
    {
        // The residualBitsSetIdx-th set of residual bits (denoted r_i
        // below) start at bit:
        //   (2*PUBLIC_VALUE_BITS) + (residualBitsSetIdx*num_residual_bits)
        //
        // Shift r_i to occupy the highest order bits:
        // 255                                       128        64           0
        //  | bits_to_shift |     | residualBitsIdx |          |           |
        //  | <------------ |<r_i>|                   |<v_pub_in>|<v_pub_out>|

        // Number of bits AFTER public values
        uint256 residualBitsIdx = residualBitsSetIdx * NUM_RESIDUAL_BITS;
        uint256 bits_to_shift =
        RESIDUAL_BITS_SHIFT - TOTAL_PUBLIC_VALUE_BITS - residualBitsIdx;
        uint256 residualBits =
            (residual << bits_to_shift) & RESIDUAL_BITS_MASK;
        return bytes32(fieldElement | residualBits);
    }
}
