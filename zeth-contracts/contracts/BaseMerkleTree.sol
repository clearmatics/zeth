// Copyright (c) 2015-2019 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

pragma solidity ^0.5.0;

// Adapted from: https://github.com/zcash-hackworks/babyzoe

contract BaseMerkleTree {
  // Index of the current node: Index to insert the next incoming commitment
  uint currentNodeIndex;

  // Array containing the 2^(depth) leaves of the merkle tree
  // We can switch the leaves to be of type bytes and not bytes32
  // to support digest of various size (eg: if we use different hash functions)
  // That way we'd have a merkle tree for any type of hash function (that can be implemented
  // as a precompiled contract for instance)
  //
  // Leaves is a 2D array
  bytes32[] leaves; // Declared as a dynamic array, the bound is put in the constructor

  // Depth of the merkle tree (should be set with the same depth set in the cpp prover)
  uint depth;

  // Number of leaves
  uint nbLeaves;

  // Debug only
  event LogDebug(bytes32 message);

  // Constructor
  constructor(uint treeDepth) public {
    depth = treeDepth;
    nbLeaves = 2**depth;

    // Initialize the merkle tree with zeroes in values
    bytes32 zeroes;
    for (uint i = 0; i < nbLeaves; i++) {
      leaves.push(zeroes);
    }
  }

  // Appends a commitment to the tree, and returns its address
  function insert(bytes32 commitment) public returns (uint) {
    // If this require fails => the merkle tree is full, we can't append leaves anymore
    require(
      currentNodeIndex < nbLeaves,
      "Merkle tree full: Cannot append anymore"
    );

    leaves[currentNodeIndex] = commitment;
    currentNodeIndex++;

    // This address can be emitted to indicate the address of the commiment
    // This is useful for the proof generation
    return currentNodeIndex - 1;
  }

  // Function that is fundamental in order to enable a client to fetch the leaves and
  // recompute the merkle tree to generate a proof (needs the merkle authentication path and the merkle tree root to be computed)
  //
  // Recomputing the merkle should not be necessary as it could be read directly from the smart contract state
  // but we'll use this function for now
  function getLeaves() public view returns (bytes32[] memory) { // returns the bytes32[] array of leaves
    bytes32[] memory tmpLeaves = new bytes32[](nbLeaves);
    for(uint i = 0; i < nbLeaves; i++) {
      tmpLeaves[i] = leaves[i];
    }

    // Returns the array of leaves of the merkle tree
    return tmpLeaves;
  }

  // Retrieve a single tree entry.  We expect that clients will generally
  // decrypt a very small fraction of new entris that appear in the tree, which
  // represents an even smaller fraction of the total tree, so in general it is
  // very inefficient for clients to download the entire tree.
  function getLeaf(uint leaf_address) public view returns (bytes32) {
      require(leaf_address < currentNodeIndex, "merkle leaf out of range");
      return leaves[leaf_address];
  }
}
