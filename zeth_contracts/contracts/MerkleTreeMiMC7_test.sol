// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.5.0;

import "./MerkleTreeMiMC7.sol";


// Simple contract used for testing MerkleTreeMiMC7.
contract MerkleTreeMiMC7_test is MerkleTreeMiMC7
{
    constructor(uint treeDepth) MerkleTreeMiMC7(treeDepth) public
    {
    }

    // Add some leaves, computing the root, then adding more leaves and
    // recomputing the root.  Returns the full set of nodes at the end.  This
    // allows testing of the update code paths for any starting / finishing
    // state combination.
    function testAddLeaves(
        bytes32[] memory first,
        bytes32[] memory second)
        public returns (bytes32[MAX_NUM_NODES] memory)
    {
        for (uint i = 0 ; i < first.length ; ++i) {
            insert(first[i]);
        }
        bytes32 root = recomputeRoot(first.length);

        for (uint i = 0 ; i < second.length ; ++i) {
            insert(second[i]);
        }
        root = recomputeRoot(second.length);
        log1(bytes32(0), root);

        return nodes;
    }
}
