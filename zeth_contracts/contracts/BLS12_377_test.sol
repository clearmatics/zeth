// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.5.0;

contract BLS12_377_test
{
    // In many cases, these numbers must be used as literals in the assembly
    // code.

    uint256 constant scalarWords = 1;
    uint256 constant scalarBytes = scalarWords * 32; // 32 (0x20)

    uint256 constant g1CoordWords = 2;
    uint256 constant g1CoordBytes = g1CoordWords * 32; // 64 (0x40)
    uint256 constant g1PointWords = 2 * g1CoordWords;
    uint256 constant g1PointBytes = g1PointWords * 32; // 128 (0x80)

    uint256 constant g2CoordWords = 4;
    uint256 constant g2CoordBytes = g2CoordWords * 32; // 128 (0x80)
    uint256 constant g2PointWords = 2 * g2CoordWords;
    uint256 constant g2PointBytes = g2PointWords * 32; // 256 (0x100)

    // `points` should be the concatenation of 2 encoded points
    function testECAdd(bytes32[2 * g1PointWords] memory points) public returns(
        bytes32[g1PointWords] memory)
    {
        bytes32[g1PointWords] memory output;
        bool success = true;
        assembly
        {
            success := call(gas, 0xc4, 0, points, 0x100, output, 0x80)
        }

        require(success, "precompiled contract call failed (ECAdd)");
        return output;
    }

    // `inputs` is an encoded point, followed by an encoded scalar.
    function testECMul(bytes32[g1PointWords + scalarWords] memory input)
        public returns(bytes32[g1PointWords] memory)
    {
        bytes32[g1PointWords] memory output;
        bool success = true;
        assembly
        {
            success := call(gas, 0xc5, 0, input, 0xa0, output, 0x80)
        }

        require(success, "precompiled contract call failed (ECMul)");
        return output;
    }

    // `points` is the concatenation of 4 pairs of encoded points. Each pair is
    // a G1 point, followed by a G2 point. For BW6-761, both of these points
    // are 6 words, so there should be 4 * 2 * 6 = 48 words.
    function testECPairing(
        bytes32[4 * (g1PointWords + g2PointWords)] memory input)
        public returns(uint256)
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
