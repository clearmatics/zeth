// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.5.0;

import "./MiMC7.sol";

// Contract to test the MiMC libraries
contract MiMC_test
{
    function test_mimc7(bytes32 x, bytes32 y) public returns (bytes32)
    {
        return MiMC7.hash(x, y);
    }
}
