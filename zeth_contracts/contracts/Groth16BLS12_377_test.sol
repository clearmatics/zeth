// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.8.0;

import "./Groth16BLS12_377.sol";

contract Groth16BLS12_377_test
{
    uint256[] private _vk;

    function verifyTest(
        uint256[] memory vk,
        uint256[] memory proof,
        uint256[] memory inputs
    )
        external
        returns(bool)
    {
        _vk = vk;
        return Groth16BLS12_377.verify(_vk, proof, inputs);
    }
}
