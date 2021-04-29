// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.8.0;

import "./LibMiMC7.sol";
import "./LibMiMC31.sol";

/// Contract to test the MiMC libraries
contract TestMiMC
{
    /// Test function for LibMiMC7
    function testMimc7(bytes32 x, bytes32 y) external pure returns (bytes32) {
        return LibMiMC7._hash(x, y);
    }

    /// Test function for LibMiMC31
    function testMimc31(bytes32 x, bytes32 y) external pure returns (bytes32) {
        return LibMiMC31._hash(x, y);
    }
}
