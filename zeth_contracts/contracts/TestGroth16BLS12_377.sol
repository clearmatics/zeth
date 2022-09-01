// Copyright (c) 2015-2022 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.8.0;

import "./LibGroth16BLS12_377.sol";

contract TestGroth16BLS12_377
{
    uint256[] private _vk;

    function testVerify(
        uint256[] memory vk,
        uint256[] memory proof,
        uint256[] memory inputs
    )
        external
        returns(bool)
    {
        _vk = vk;
        return LibGroth16BLS12_377._verify(_vk, proof, inputs);
    }
}
