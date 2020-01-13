// Copyright (c) 2015-2019 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.5.0;

import "./BaseMerkleTree.sol";
import "./MiMC7.sol";

contract MerkleTreeMiMC7 is BaseMerkleTree {

    constructor(uint256 treeDepth) BaseMerkleTree(treeDepth) public {
    }

    // Returns the root of the merkle tree
    function getRoot() internal view returns(bytes32) {
        uint256 layerSize = nbLeaves / 2;
        bytes32[nbLeaves/2] memory pad;

        // Compute first layer from storage
        for (uint256 i = 0 ; i < layerSize ; ++i) {
            pad[i] = MiMC7.hash(leaves[2*i], leaves[2*i + 1]);
        }
        layerSize = layerSize / 2;

        // Compute successive layers from their parents, in-place.
        for ( ; layerSize > 0 ; layerSize = layerSize / 2) {
            for (uint256 i = 0 ; i < layerSize ; ++i) {
                pad[i] = MiMC7.hash(pad[2*i], pad[2*i + 1]);
            }
        }

        return pad[0];
    }
}
