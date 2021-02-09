// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.8.0;

import "./BaseMerkleTree.sol";

contract MerkleTreeSha256 is BaseMerkleTree
{

    constructor(uint256 treeDepth) public BaseMerkleTree(treeDepth)
    {
    }

    /// Returns the current merkle tree
    function getTree() internal view returns (bytes32[] memory)
    {
        uint256 nbNodes = 2**(depth + 1) - 1;
        bytes32[] memory tmpTree = new bytes32[](nbNodes);

        // Dump the leaves in the right indexes in the tree
        for (uint256 i = 0; i < nbLeaves; i++) {
            tmpTree[(nbLeaves - 1) + i] = leaves[i];
        }

        // Compute the internal nodes of the merkle tree
        for (uint256 i = nbLeaves - 2; i > 0; i--) {
            tmpTree[i] = sha256(
                abi.encodePacked(tmpTree[i*2+1], tmpTree[2*(i+1)]));
        }

        // Compute the merkle root
        tmpTree[0] = sha256(abi.encodePacked(tmpTree[1], tmpTree[2]));

        return tmpTree;
    }

    /// Returns the root of the merkle tree
    function getRoot() internal view returns(bytes32)
    {
        return getTree()[0];
    }
}
