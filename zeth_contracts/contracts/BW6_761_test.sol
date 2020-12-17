// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.5.0;

contract BW6_761_test
{
    // In many cases, these numbers must be used as literals in the assembly
    // code.

    uint256 internal constant SCALAR_WORDS = 2;
    uint256 internal constant SCALAR_BYTES = SCALAR_WORDS * 32; // 64 (0x40)
    uint256 internal constant COORD_WORDS = 3;
    uint256 internal constant COORD_BYTES = 3 * 32; // 96 (0x60)
    uint256 internal constant POINT_WORDS = 2 * COORD_WORDS;
    uint256 internal constant POINT_BYTES = POINT_WORDS * 32; // 192 (0xc0)

    // `points` should be the concatenation of 2 encoded points
    function testECAdd(bytes32[2 * POINT_WORDS] memory points)
        public returns (bytes32[POINT_WORDS] memory)
    {
        bytes32[POINT_WORDS] memory output;
        bool success = true;
        assembly
        {
            success := call(gas, 0xc1, 0, points, 0x180, output, 0xc0)
        }

        require(success, "precompiled contract call failed (ECAdd)");
        return output;
    }

    // `inputs` is an encoded point, followed by an encoded scalar.
    function testECMul(bytes32[POINT_WORDS + SCALAR_WORDS] memory input)
        public returns (bytes32[POINT_WORDS] memory)
    {
        bytes32[POINT_WORDS] memory output;
        bool success = true;
        assembly
        {
            success := call(gas, 0xc2, 0, input, 0x100, output, 0xc0)
        }

        require(success, "precompiled contract call failed (ECMul)");
        return output;
    }

    // `points` is the concatenation of 4 pairs of encoded points. Each pair is
    // a G1 point, followed by a G2 point. For BW6-761, both of these points
    // are 6 words, so there should be 4 * 2 * 6 = 48 words (
    function testECPairing(bytes32[8 * POINT_WORDS] memory input)
        public returns (uint256)
    {
        uint256[1] memory output;
        bool success = true;
        assembly
        {
            success := call(gas, 0xc3, 0, input, 0x600, output, 0x20)
        }

        require(success, "precompiled contract call failed (ECMul)");
        return output[0];
    }
}
