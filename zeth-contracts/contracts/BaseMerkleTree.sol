// Copyright (c) 2015-2019 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.5.0;

// Adapted from: https://github.com/zcash-hackworks/babyzoe

contract BaseMerkleTree {
    // Depth of the merkle tree (should be set with the same depth set in the
    // cpp prover)
    uint256 constant depth = 4;

    // Number of leaves
    uint256 constant nbLeaves = 2**depth;

    //
    bytes32 constant DEFAULT_LEAF_VALUE = 0x0;

    // Index of the current node: Index to insert the next incoming commitment
    uint256 currentNodeIndex;

    // Array containing the 2^(depth) leaves of the merkle tree.  We can switch
    // the leaves to be of type bytes and not bytes32 to support digest of
    // various size (eg: if we use different hash functions).  That way we'd
    // have a merkle tree for any type of hash function (that can be implemented
    // as a precompiled contract for instance)
    //
    // Leaves is a 2D array

    // Sparse array of populated leaves of the merkle tree.  Unpopulated leaves
    // have the DEFAULT_LEAF_VALUE.

    bytes32[] leaves;

    // Debug only
    event LogDebug(bytes32 message);

    // Constructor
    constructor(uint256 treeDepth) public {
        require (
            treeDepth == depth,
            "Invalid depth in BaseMerkleTree");
    }

    // Appends a commitment to the tree, and returns its address
    function insert(bytes32 commitment) public returns (uint) {

        // Address of the next leaf is the current length (before insertion).
        uint next_address = leaves.length;

        // If this require fails => the merkle tree is full, we can't append
        // leaves anymore.
        require(
            next_address < nbLeaves,
            "Merkle tree full: Cannot append anymore"
        );

        leaves.push(commitment);
        return next_address;

        /* leaves[currentNodeIndex] = commitment; */
        /* currentNodeIndex++; */

        /* // This address can be emitted to indicate the address of the commiment */
        /* // This is useful for the proof generation */
        /* return currentNodeIndex - 1; */
    }
}
