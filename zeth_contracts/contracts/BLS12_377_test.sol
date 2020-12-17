// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.5.0;

contract BLS12_377_test
{
    // In many cases, these numbers must be used as literals in the assembly
    // code.

    uint256 internal constant SCALAR_WORDS = 1;
    uint256 internal constant SCALAR_BYTES = SCALAR_WORDS * 32; // 32 (0x20)

    uint256 internal constant G1_COORD_WORDS = 2;
    uint256 internal constant G1_COORD_BYTES = G1_COORD_WORDS * 32; // 64 (0x40)
    uint256 internal constant G1_POINT_WORDS = 2 * G1_COORD_WORDS;
    uint256 internal constant G1_POINT_BYTES = G1_POINT_WORDS * 32; // 128 (0x80)

    uint256 internal constant G2_COORD_WORDS = 4;
    uint256 internal constant G2_COORD_BYTES = G2_COORD_WORDS * 32; // 128 (0x80)
    uint256 internal constant G2_POINT_WORDS = 2 * G2_COORD_WORDS;
    uint256 internal constant G2_POINT_BYTES = G2_POINT_WORDS * 32; // 256 (0x100)

    /// `input` is the concatenation of 2 encoded points in G1
    function testECAdd(bytes32[2 * G1_POINT_WORDS] memory input) public returns(
        bytes32[G1_POINT_WORDS] memory)
    {
        bytes32[G1_POINT_WORDS] memory output;
        bool success = true;
        assembly
        {
            success := call(gas, 0xc4, 0, input, 0x100, output, 0x80)
        }

        require(success, "precompiled contract call failed (ECAdd)");
        return output;
    }

    /// `input` is an encoded point in G1, followed by an encoded scalar.
    function testECMul(bytes32[G1_POINT_WORDS + SCALAR_WORDS] memory input)
        public returns(bytes32[G1_POINT_WORDS] memory)
    {
        bytes32[G1_POINT_WORDS] memory output;
        bool success = true;
        assembly
        {
            success := call(gas, 0xc5, 0, input, 0xa0, output, 0x80)
        }

        require(success, "precompiled contract call failed (ECMul)");
        return output;
    }

    /// `input` is the concatenation of 4 pairs of encoded points. Each pair is
    /// a G1 point, followed by a G2 point. For BW6-761, both of these points
    /// are 6 words, so there should be 4 * 2 * 6 = 48 words.
    function testECPairing(
        bytes32[4 * (G1_POINT_WORDS + G2_POINT_WORDS)] memory input
    )
        public
        returns(uint256)
    {
        uint256[1] memory output;
        bool success = true;
        assembly
        {
            success := call(gas, 0xc6, 0, input, 0x600, output, 0x20)
        }

        require(success, "precompiled contract call failed (ECMul)");
        return output[0];
    }
}
