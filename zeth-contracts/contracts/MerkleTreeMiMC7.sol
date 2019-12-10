// Copyright (c) 2015-2019 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.5.0;

import "./BaseMerkleTree.sol";
import "./MiMC7.sol";

contract MerkleTreeMiMC7 is BaseMerkleTree {

    constructor(uint treeDepth) BaseMerkleTree(treeDepth) public {
    }

    // Returns the current merkle tree
    function getTree() public view returns (bytes32[] memory) {
        uint nbNodes = 2**(depth + 1) - 1;
        bytes32[] memory tmpTree = new bytes32[](nbNodes);
        bytes32 left;
        bytes32 right;
        // Dump the leaves in the right indexes in the tree
        for (uint i = 0; i < nbLeaves; i++) {
            tmpTree[(nbLeaves - 1) + i] = leaves[i];
        }

        // Compute the internal nodes of the merkle tree
        for (uint i = nbLeaves - 2; i > 0; i--) {
            left = tmpTree[2*i+1];
            right = tmpTree[2*(i+1)];

            // Seed is hardcoded and given by "clearmatics_mt_seed"
            tmpTree[i] = MiMC7.hash(left, right);
        }

        // Compute the merkle root
        left = tmpTree[1];
        right = tmpTree[2];
        tmpTree[0] = MiMC7.hash(left, right);

        return tmpTree;
    }

    // Returns the root of the merkle tree
    function getRoot() public view returns(bytes32) {
        uint layerSize = nbLeaves / 2;
        bytes32[nbLeaves/2] memory pad;

        // Compute first layer from storage
        for (uint i = 0 ; i < layerSize ; ++i) {
            pad[i] = MiMC7.hash(leaves[2*i], leaves[2*i + 1]);
        }
        layerSize = layerSize / 2;

        // Compute successive layers from their parents, in-place.
        for ( ; layerSize > 0 ; layerSize = layerSize / 2) {
            for (uint i = 0 ; i < layerSize ; ++i) {
                pad[i] = MiMC7.hash(pad[2*i], pad[2*i + 1]);
            }
        }

        return pad[0];
    }
}
