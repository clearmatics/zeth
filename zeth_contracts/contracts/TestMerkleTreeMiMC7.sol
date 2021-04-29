// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.8.0;

import "./AbstractMerkleTree.sol";
import "./LibMiMC7.sol";

/// The Merkle tree implementation must trade-off complexity, storage,
/// initialization cost, and update & root computation cost.
///
/// This implementation stores all leaves and nodes, skipping those that have
/// not been populated yet. The final entry in each layer stores that layer's
/// default value.
contract TestMerkleTreeMiMC7 is AbstractMerkleTree
{
    constructor(uint treeDepth) AbstractMerkleTree(treeDepth)
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
        external
        returns (bytes32)
    {
        for (uint i = 0 ; i < first.length ; ++i) {
            insert(first[i]);
        }
        bytes32 root = _recomputeRoot(first.length);

        for (uint i = 0 ; i < second.length ; ++i) {
            insert(second[i]);
        }
        root = _recomputeRoot(second.length);
        return root;
    }

    /// Use MiMC7 as the Merkle tree hash function.
    function _hash(bytes32 left, bytes32 right)
        internal
        pure
        override
        returns(bytes32)
    {
        return LibMiMC7._hash(left, right);
    }
}
