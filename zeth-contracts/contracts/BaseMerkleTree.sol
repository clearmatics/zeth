// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.5.0;

// Adapted from: https://github.com/zcash-hackworks/babyzoe

contract BaseMerkleTree {
    // Depth of the merkle tree (should be set with the same depth set in the
    // cpp prover)
    uint256 constant DEPTH = 32;

    // Number of leaves
    uint256 constant MAX_NUM_LEAVES = 2**DEPTH;

    // Number of nodes
    uint constant MAX_NUM_NODES = (MAX_NUM_LEAVES * 2) - 1;

    bytes32 constant DEFAULT_LEAF_VALUE = 0x0;

    // Array containing the 2^(depth) leaves of the merkle tree.  We can switch
    // the leaves to be of type bytes and not bytes32 to support digest of
    // various size (eg: if we use different hash functions).  That way we'd
    // have a merkle tree for any type of hash function (that can be implemented
    // as a precompiled contract for instance)
    //
    // Leaves is a 2D array

    // Sparse array of populated leaves of the merkle tree.  Unpopulated leaves
    // have the DEFAULT_LEAF_VALUE.

    bytes32[MAX_NUM_NODES] nodes;

    // Number of leaves populated in `nodes`.
    uint256 num_leaves;

    // Debug only
    event LogDebug(bytes32 message);

    // Constructor
    constructor(uint256 treeDepth) public {
        require (
            treeDepth == DEPTH,
            "Invalid depth in BaseMerkleTree");
    }

    // Appends a commitment to the tree, and returns its address
    function insert(bytes32 commitment) public returns (uint) {

        // If this require fails => the merkle tree is full, we can't append
        // leaves anymore.
        require(
            num_leaves < MAX_NUM_LEAVES,
            "Merkle tree full: Cannot append anymore"
        );

        // Address of the next leaf is the current number of leaves (before
        // insertion).  Compute the next index in the full set of nodes, and
        // write.
        uint256 next_address = num_leaves;
        ++num_leaves;
        uint256 next_entry_idx = (MAX_NUM_LEAVES - 1) + next_address;
        nodes[next_entry_idx] = commitment;
        return next_address;
    }
}
