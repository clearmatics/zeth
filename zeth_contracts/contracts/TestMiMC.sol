// Copyright (c) 2015-2022 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.8.0;

import "./LibMiMC.sol";

/// Contract to test the MiMC libraries
contract TestMiMC
{
    /// Test function for LibMiMC._hashAltBN128
    function testMimcAltBN128(bytes32 x, bytes32 y)
        external
        pure
        returns (bytes32) {
        return LibMiMC._hashAltBN128(x, y);
    }

    /// Test function for LibMiMC._hashBLS12_377
    function testMimcBLS12_377(bytes32 x, bytes32 y)
        external
        pure
        returns (bytes32) {
        return LibMiMC._hashBLS12_377(x, y);
    }
}
