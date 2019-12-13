// Copyright (c) 2015-2019 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.5.0;

import "./BaseMerkleTree.sol";
import "./MiMC7.sol";

contract MerkleTreeMiMC7 is BaseMerkleTree {
  // Custom hash smart contract
  MiMC7 public mimc7_hasher;

  constructor(address hasher_address, uint treeDepth) BaseMerkleTree(treeDepth) public {
    mimc7_hasher = MiMC7(hasher_address);
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
      tmpTree[i] = mimc7_hasher.hash(left, right, "clearmatics_mt_seed");
    }

    // Compute the merkle root
    left = tmpTree[1];
    right = tmpTree[2];
    tmpTree[0] = mimc7_hasher.hash(left, right, "clearmatics_mt_seed");

    return tmpTree;
  }

  // Returns the root of the merkle tree
  function getRoot() public view returns(bytes32) {
    return getTree()[0];
  }
}
