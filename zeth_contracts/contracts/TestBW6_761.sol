// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.8.0;

contract TestBW6_761
{
    // In many cases, these numbers must be used as literals in the assembly
    // code.

    uint256 private constant _SCALAR_WORDS = 2;
    uint256 private constant _COORD_WORDS = 3;
    uint256 private constant _POINT_WORDS = 2 * _COORD_WORDS;

    /// `input` is the concatenation of 2 encoded points in G1
    function ecAddTest(bytes32[2 * _POINT_WORDS] memory input)
        external returns (bytes32[_POINT_WORDS] memory)
    {
        bytes32[_POINT_WORDS] memory output;
        bool success = true;
        assembly
        {
            success := call(gas(), 0xc1, 0, input, 0x180, output, 0xc0)
        }

        require(success, "precompiled contract call failed (ECAdd)");
        return output;
    }

    // `input` is an encoded point, followed by an encoded scalar.
    function ecMulTest(bytes32[_POINT_WORDS + _SCALAR_WORDS] memory input)
        external returns (bytes32[_POINT_WORDS] memory)
    {
        bytes32[_POINT_WORDS] memory output;
        bool success = true;
        assembly
        {
            success := call(gas(), 0xc2, 0, input, 0x100, output, 0xc0)
        }

        require(success, "precompiled contract call failed (ECMul)");
        return output;
    }

    // `input` is the concatenation of 4 pairs of encoded points. Each pair is
    // a G1 point, followed by a G2 point. For BW6-761, both of these points
    // are 6 words, so there should be 4 * 2 * 6 = 48 words (
    function ecPairingTest(bytes32[8 * _POINT_WORDS] memory input)
        external returns (uint256)
    {
        uint256[1] memory output;
        bool success = true;
        assembly
        {
            success := call(gas(), 0xc3, 0, input, 0x600, output, 0x20)
        }

        require(success, "precompiled contract call failed (ECMul)");
        return output[0];
    }
}
