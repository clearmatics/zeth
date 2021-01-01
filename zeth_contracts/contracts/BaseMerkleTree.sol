// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.5.0;

/// Abstract Merkle tree implementation. Child classes should implement the
/// hash function.
///
/// The Merkle tree implementation must trade-off complexity, storage,
/// initialization cost, and update & root computation cost.
///
/// This implementation stores all leaves and nodes, skipping those that have
/// not been populated yet. The final entry in each layer stores that layer's
/// default value.
contract BaseMerkleTree
{
    // Depth of the merkle tree (should be set with the same depth set in the
    // cpp prover)
    uint256 internal constant DEPTH = 32;

    // Number of leaves
    uint256 internal constant MAX_NUM_LEAVES = 2**DEPTH;

    // Number of nodes
    uint256 internal constant MAX_NUM_NODES = (MAX_NUM_LEAVES * 2) - 1;

    uint256 internal constant MASK_LS_BIT = ~uint256(1);

    bytes32 internal constant DEFAULT_LEAF_VALUE = 0x0;

    // Sparse array of populated leaves of the merkle tree.
    // Unpopulated leaves have the DEFAULT_LEAF_VALUE.
    bytes32[MAX_NUM_NODES] internal nodes;

    // Number of leaves populated in `nodes`.
    uint256 internal num_leaves;

    // Debug only
    event LogDebug(bytes32 message);

    /// Constructor
    constructor(uint256 treeDepth) public {
        require (
            treeDepth == DEPTH,
            "Invalid depth in BaseMerkleTree"
        );
        initializeTree();
    }

    /// Appends a commitment to the tree, and returns its address
    function insert(bytes32 commitment) public {
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
    }

    /// Abstract hash function to be supplied by a concrete implementation of
    /// this class.
    function hash(bytes32 left, bytes32 right) internal returns (bytes32);

    function recomputeRoot(uint num_new_leaves) internal returns (bytes32) {
        // Assume `num_new_leaves` have been written into the leaf slots.
        // Update any affected nodes in the tree, up to the root, using the
        // default values for any missing nodes.

        uint256 end_idx = num_leaves;
        uint256 start_idx = num_leaves - num_new_leaves;
        uint256 layer_size = MAX_NUM_LEAVES;

        while (layer_size > 1) {
            (start_idx, end_idx) =
                recomputeParentLayer(layer_size, start_idx, end_idx);
            layer_size = layer_size / 2;
        }

        return nodes[0];
    }

    function initializeTree() private {
        // First layer
        bytes32 default_value = DEFAULT_LEAF_VALUE;
        nodes[2 * MAX_NUM_LEAVES - 2] = default_value;
        uint256 layer_size = MAX_NUM_LEAVES / 2;

        // Subsequent layers
        while (layer_size > 0) {
            default_value = hash(default_value, default_value);
            uint256 layer_final_entry_idx = 2 * layer_size - 2;
            nodes[layer_final_entry_idx] = default_value;
            layer_size = layer_size / 2;
        }
    }

    /// Recompute nodes in the parent layer that are affected by entries
    /// [child_start_idx, child_end_idx[ in the child layer.  If
    /// `child_end_idx` is required in the calculation, the final entry of
    /// the child layer is used (since this contains the default entry for
    /// the layer if the tree is not full).
    ///
    ///            /     \         /     \         /     \
    /// Parent:   ?       ?       F       G       H       0
    ///          / \     / \     / \     / \     / \     / \
    /// Child:  ?   ?   ?   ?   A   B   C   D   E   ?   ?   0
    ///                         ^                   ^
    ///                child_start_idx         child_end_idx
    ///
    /// Returns the start and end indices (within the parent layer) of touched
    /// parent nodes.
    function recomputeParentLayer(
        uint256 child_layer_size,
        uint256 child_start_idx,
        uint256 child_end_idx
    )
        private
        returns (uint256, uint256)
    {
        uint256 child_layer_start = child_layer_size - 1;

        // Start at the right and iterate left, so we only execute the
        // default_value logic once.  child_left_idx_rend (reverse-end) is the
        // smallest value of child_left_idx at which we should recompute the
        // parent node hash.

        uint256 child_left_idx_rend =
            child_layer_start + (child_start_idx & MASK_LS_BIT);

        // If child_end_idx is odd, it is the RIGHT of a computation we need
        // to make. Do the computation using the default value, and move to
        // the next pair (on the left).
        // Otherwise, we have a fully populated pair.

        uint256 child_left_idx;
        if ((child_end_idx & 1) != 0) {
            child_left_idx = child_layer_start + child_end_idx - 1;
            nodes[(child_left_idx - 1) / 2] =
                hash(nodes[child_left_idx], nodes[2 * child_layer_start]);
        } else {
            child_left_idx = child_layer_start + child_end_idx;
        }

        // At this stage, pairs are all populated. Compute until we reach
        // child_left_idx_rend.

        while (child_left_idx > child_left_idx_rend) {
            child_left_idx = child_left_idx - 2;
            nodes[(child_left_idx - 1) / 2] =
                hash(nodes[child_left_idx], nodes[child_left_idx + 1]);
        }

        return (child_start_idx / 2, (child_end_idx + 1) / 2);
    }
}
