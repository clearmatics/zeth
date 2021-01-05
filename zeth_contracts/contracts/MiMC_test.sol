// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.5.0;

import "./MiMC7.sol";
import "./MiMC31.sol";

/// Contract to test the MiMC libraries
contract MiMC_test
{
    /// Test function for MiMC7
    function test_mimc7(bytes32 x, bytes32 y) public returns (bytes32) {
        return MiMC7.hash(x, y);
    }

    /// Test function for MiMC31
    function test_mimc31(bytes32 x, bytes32 y) public returns (bytes32) {
        return MiMC31.hash(x, y);
    }
}
