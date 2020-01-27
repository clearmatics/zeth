// Copyright (c) 2015-2019 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.5.0;

import "./BaseMerkleTree.sol";
import "./MiMC7.sol";

contract MerkleTreeMiMC7 is BaseMerkleTree {

    constructor(uint256 treeDepth) BaseMerkleTree(treeDepth) public {
    }

    // Assume a layer, with size `layer_size` where `num_present` entries are
    // populated, and all other entries take the value `default_value`.  Compute
    // the next layer, into the same buffer.  Returns the number of values
    // present in the new later, and the default value for entries that are not
    // present.
    function reduceSparseLayer(
        bytes32[nbLeaves/2] memory pad,
        uint256 num_present,
        uint256 layer_size,
        bytes32 default_value) internal pure returns (uint256, bytes32) {

        require (num_present <= layer_size, "invalid num_present");

        // Each entry in the new layer is computed from 2 entries LEFT and RIGHT
        // in the current later.  Compute:
        //   `num_full_present` - num entries where LEFT and RIGHT both present
        //   `num_partial_present` - num entries where only LEFT present
        uint256 num_full_present = num_present / 2;
        uint256 num_partial_present = num_present & 1;

        uint256 i = 0;
        for ( ; i < num_full_present ; ++i) {
            pad[i] = MiMC7.hash(pad[2 * i], pad[2*i + 1]);
        }
        if (num_partial_present > 0) {
            pad[i] = MiMC7.hash(pad[2 * i], default_value);
            ++i;
        }

        if (num_present < layer_size - 1) {
            default_value = MiMC7.hash(default_value, default_value);
        }

        return (i, default_value);
    }

    // Returns the root of the merkle tree
    function getRoot() internal view returns(bytes32) {
        uint256 layer_size = nbLeaves / 2;
        uint256 num_present = leaves.length;

        // Create a statically sized array for the largest possible required
        // length (to avoid the cost of a dynamic one).  As long as this and all
        // child functions do not use memory AFTER `pad`, we should only pay gas
        // for the memory actually used - not necessarily the full array.
        bytes32[nbLeaves / 2] memory pad;

        // Compute first layer from storage
        uint256 i = 0;
        for ( ; i < num_present / 2 ; ++i) {
            pad[i] = MiMC7.hash(leaves[2*i], leaves[2*i + 1]);
        }
        if ((num_present & 1) != 0) {
            pad[i] = MiMC7.hash(leaves[2*i], DEFAULT_LEAF_VALUE);
            i++;
        }

        bytes32 default_value = MiMC7.hash(DEFAULT_LEAF_VALUE, DEFAULT_LEAF_VALUE);
        num_present = i;
        while (layer_size > 1) {
            (num_present, default_value) = reduceSparseLayer(
                pad, num_present, layer_size, default_value);
            layer_size = layer_size / 2;
        }

        if (num_present > 0) {
            return pad[0];
        }

        return default_value;
    }
}
