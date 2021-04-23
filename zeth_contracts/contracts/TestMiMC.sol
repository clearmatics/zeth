// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.8.0;

import "./LMiMC7.sol";
import "./LMiMC31.sol";

/// Contract to test the MiMC libraries
contract TestMiMC
{
    /// Test function for LMiMC7
    function mimc7Test(bytes32 x, bytes32 y) external pure returns (bytes32) {
        return LMiMC7._hash(x, y);
    }

    /// Test function for LMiMC31
    function mimc31Test(bytes32 x, bytes32 y) external pure returns (bytes32) {
        return LMiMC31._hash(x, y);
    }
}
