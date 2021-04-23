// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.8.0;

import "./BaseMixer.sol";
import "./LMiMC7.sol";

/// Partial implementation of abstract BaseMixer which implements the
/// curve-specific methods to use the ALT-BN128 pairing.
abstract contract BaseMixerAltBN128 is BaseMixer
{
    // Constants regarding the _hash digest length, the prime number used and
    // its associated length in bits and the max values (v_in and v_out)
    // FIELD_CAPACITY = floor( log_2(r) )
    uint256 internal constant _FIELD_CAPACITY = 253;

    // Number of residual bits per bytes32
    uint256 internal constant _NUM_RESIDUAL_BITS =
        _DIGEST_LENGTH - _FIELD_CAPACITY;

    // Shift to move residual bits from lowest order to highest order
    uint256 internal constant _RESIDUAL_BITS_SHIFT = 256 - _NUM_RESIDUAL_BITS;

    // Mask to extract the residual bits in the high-order position
    uint256 internal constant _RESIDUAL_BITS_MASK =
        ((1 << _NUM_RESIDUAL_BITS) - 1) << _RESIDUAL_BITS_SHIFT;

    /// Constructor of the contract
    constructor(
        uint256 mkDepth,
        address token,
        uint256[] memory vk,
        address permittedDispatcher,
        uint256[2] memory vkHash
    )
        BaseMixer(mkDepth, token, vk, permittedDispatcher, vkHash)
    {
    }

    /// Use LMiMC7 as the Merkle tree _hash function.
    function _hash(bytes32 left, bytes32 right)
        internal
        pure
        override
        returns(bytes32)
    {
        return LMiMC7._hash(left, right);
    }

    /// Utility function to extract a full uint256 from a field element and the
    /// n-th set of residual bits from `residual`.
    function _extractBytes32(
        uint256 fieldElement,
        uint256 residual,
        uint256 residualBitsSetIdx
    )
        internal
        pure
        override
        returns(bytes32)
    {
        // The residual bits are located at:
        //  (2*public_value_bits) + (residualBitsSetIdx*NUM_RESIDUAL_BITS)
        //
        // Shift to occupy the highest order bits:
        // 255                                       128         64           0
        //  |  bitsToShift  |     |  residualBitsIdx  |           |           |
        //  | <------------ | xxx |                   |<v_pub_in>)|<v_pub_out>|
        //                residual bits

        // Number of bits AFTER public values
        uint256 residualBitsIdx = residualBitsSetIdx * _NUM_RESIDUAL_BITS;
        uint256 bitsToShift =
            _RESIDUAL_BITS_SHIFT - _TOTAL_PUBLIC_VALUE_BITS - residualBitsIdx;
        uint256 residualBits =
            (residual << bitsToShift) & _RESIDUAL_BITS_MASK;
        return bytes32(fieldElement | residualBits);
    }
}
