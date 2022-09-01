// Copyright (c) 2015-2022 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.8.0;

/// Abstract Merkle tree implementation. Child classes should implement the
/// hash function.
///
/// The Merkle tree implementation must trade-off complexity, storage,
/// initialization cost, and update & root computation cost.
///
/// This implementation stores all leaves and nodes, skipping those that have
/// not been populated yet. The final entry in each layer stores that layer's
/// default value.
abstract contract AbstractMerkleTree
{
    // Depth of the merkle tree (should be set with the same depth set in the
    // cpp prover)
    uint256 internal constant _DEPTH = 32;

    // Maximum number of leaves in the tree
    uint256 internal constant _MAX_NUM_LEAVES = 2**_DEPTH;

    // Maximum number of nodes in the tree
    uint256 internal constant _MAX_NUM_NODES = (_MAX_NUM_LEAVES * 2) - 1;

    uint256 internal constant _MASK_LS_BIT = ~uint256(1);

    bytes32 internal constant _DEFAULT_LEAF_VALUE = 0x0;

    // Sparse array of populated leaves of the merkle tree.
    // Unpopulated leaves have the _DEFAULT_LEAF_VALUE.
    bytes32[_MAX_NUM_NODES] internal _nodes;

    // Number of leaves populated in `_nodes`.
    uint256 internal _numLeaves;

    /// Constructor
    constructor(uint256 treeDepth) {
        require (
            treeDepth == _DEPTH,
            "Invalid depth in AbstractMerkleTree"
        );
        _initializeTree();
    }

    /// Appends a commitment to the tree, and returns its address
    function insert(bytes32 commitment) public {
        // If this require fails => the merkle tree is full, we can't append
        // leaves anymore.
        require(
            _numLeaves < _MAX_NUM_LEAVES,
            "Merkle tree full: Cannot append anymore"
        );

        // Address of the next leaf is the current number of leaves (before
        // insertion).  Compute the next index in the full set of nodes, and
        // write.
        uint256 next_address = _numLeaves;
        ++_numLeaves;
        uint256 next_entry_idx = (_MAX_NUM_LEAVES - 1) + next_address;
        _nodes[next_entry_idx] = commitment;
    }

    /// Abstract hash function to be supplied by a concrete implementation of
    /// this class.
    function _hash(bytes32 left, bytes32 right)
        internal
        virtual
        returns (bytes32);

    function _recomputeRoot(uint numNewLeaves) internal returns (bytes32) {
        // Assume `numNewLeaves` have been written into the leaf slots.
        // Update any affected nodes in the tree, up to the root, using the
        // default values for any missing nodes.

        uint256 end_idx = _numLeaves;
        uint256 start_idx = _numLeaves - numNewLeaves;
        uint256 layer_size = _MAX_NUM_LEAVES;

        while (layer_size > 1) {
            (start_idx, end_idx) =
                _recomputeParentLayer(layer_size, start_idx, end_idx);
            layer_size = layer_size / 2;
        }

        return _nodes[0];
    }

    function _initializeTree() private {
        // First layer
        bytes32 default_value = _DEFAULT_LEAF_VALUE;
        _nodes[2 * _MAX_NUM_LEAVES - 2] = default_value;
        uint256 layer_size = _MAX_NUM_LEAVES / 2;

        // Subsequent layers
        while (layer_size > 0) {
            default_value = _hash(default_value, default_value);
            uint256 layer_final_entry_idx = 2 * layer_size - 2;
            _nodes[layer_final_entry_idx] = default_value;
            layer_size = layer_size / 2;
        }
    }

    /// Recompute nodes in the parent layer that are affected by entries
    /// [childStartIdx, childEndIdx[ in the child layer.  If
    /// `childEndIdx` is required in the calculation, the final entry of
    /// the child layer is used (since this contains the default entry for
    /// the layer if the tree is not full).
    ///
    ///            /     \         /     \         /     \
    /// Parent:   ?       ?       F       G       H       0
    ///          / \     / \     / \     / \     / \     / \
    /// Child:  ?   ?   ?   ?   A   B   C   D   E   ?   ?   0
    ///                         ^                   ^
    ///                childStartIdx         childEndIdx
    ///
    /// Returns the start and end indices (within the parent layer) of touched
    /// parent nodes.
    function _recomputeParentLayer(
        uint256 childLayerSize,
        uint256 childStartIdx,
        uint256 childEndIdx
    )
        private
        returns (uint256, uint256)
    {
        uint256 child_layer_start = childLayerSize - 1;

        // Start at the right and iterate left, so we only execute the
        // default_value logic once.  child_left_idx_rend (reverse-end) is the
        // smallest value of child_left_idx at which we should recompute the
        // parent node hash.

        uint256 child_left_idx_rend =
            child_layer_start + (childStartIdx & _MASK_LS_BIT);

        // If childEndIdx is odd, it is the RIGHT of a computation we need
        // to make. Do the computation using the default value, and move to
        // the next pair (on the left).
        // Otherwise, we have a fully populated pair.

        uint256 child_left_idx;
        if ((childEndIdx & 1) != 0) {
            child_left_idx = child_layer_start + childEndIdx - 1;
            _nodes[(child_left_idx - 1) / 2] =
                _hash(_nodes[child_left_idx], _nodes[2 * child_layer_start]);
        } else {
            child_left_idx = child_layer_start + childEndIdx;
        }

        // At this stage, pairs are all populated. Compute until we reach
        // child_left_idx_rend.

        while (child_left_idx > child_left_idx_rend) {
            child_left_idx = child_left_idx - 2;
            _nodes[(child_left_idx - 1) / 2] =
                _hash(_nodes[child_left_idx], _nodes[child_left_idx + 1]);
        }

        return (childStartIdx / 2, (childEndIdx + 1) / 2);
    }
}
