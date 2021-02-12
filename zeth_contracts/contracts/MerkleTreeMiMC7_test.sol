// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.8.0;

import "./BaseMerkleTree.sol";
import "./MiMC7.sol";

/// The Merkle tree implementation must trade-off complexity, storage,
/// initialization cost, and update & root computation cost.
///
/// This implementation stores all leaves and nodes, skipping those that have
/// not been populated yet. The final entry in each layer stores that layer's
/// default value.
contract MerkleTreeMiMC7_test is BaseMerkleTree
{
    constructor(uint treeDepth) public BaseMerkleTree(treeDepth)
    {
    }

    /// Add some leaves, computing the root, then adding more leaves and
    /// recomputing the root.  Returns the full set of nodes at the end.  This
    /// allows testing of the update code paths for any starting / finishing
    /// state combination.
    function testAddLeaves(
        bytes32[] memory first,
        bytes32[] memory second
    )
        public
        returns (bytes32)
    {
        for (uint i = 0 ; i < first.length ; ++i) {
            insert(first[i]);
        }
        bytes32 root = recomputeRoot(first.length);

        for (uint i = 0 ; i < second.length ; ++i) {
            insert(second[i]);
        }
        root = recomputeRoot(second.length);
        return root;
    }

    /// Use MiMC7 as the Merkle tree hash function.
    function hash(bytes32 left, bytes32 right)
        internal
        override
        returns(bytes32)
    {
        return MiMC7.hash(left, right);
    }
}
