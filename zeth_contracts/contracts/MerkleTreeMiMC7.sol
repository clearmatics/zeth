// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^ 0.5.0;

import "./BaseMerkleTree.sol";
import "./MiMC7.sol";

contract MerkleTreeMiMC7 is BaseMerkleTree
{
    constructor(uint256 treeDepth) BaseMerkleTree(treeDepth) public {}

    function hash(bytes32 left, bytes32 right) internal returns(bytes32)
    {
        return MiMC7.hash(left, right);
    }
}
