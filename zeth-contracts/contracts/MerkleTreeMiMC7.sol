solidity ^0.5.0;

import "./BaseMerkleTree.sol";
import "./MiMC7.sol"

contract MerkleTreeMiMC7 is BaseMerkleTree {
  // Custom hash smart contract
  MiMC7 public mimc7_hasher;

  // Constructor
  constructor(address hasher_address, uint treeDepth) BaseMerkleTree(treeDepth) {
    mimc7_hasher = MiMC7(hasher_address);
  }

  // This function is constrainted to be internal by the fact that we return a bytes[]
  // If we want to make it public and use a stable version of the solidity compiler, we need
  // to switch to bytes32[] (and thus only hash functions with digest of length < 256bits)
  // would be supported in the merkle tree.
  //
  // Note: This function diverges a little bit from the standard implementations
  // because we usually affect the node index 1 to the root and follow the convention
  // to append 0 if we go left or 1 if we go right in the merkle tree
  // However, here we start at the index 0 for the merkle tree
  function getTree() public view returns (bytes32[] memory) {
    uint nbNodes = 2**(depth + 1) - 1;
    bytes32[] memory tmpTree = new bytes32[](nbNodes);

    // Dump the leaves in the right indexes in the tree
    for (uint i = 0; i < nbLeaves; i++) {
      tmpTree[(nbLeaves - 1) + i] = leaves[i];
    }

    // Compute the internal nodes of the merkle tree
    for (uint i = nbLeaves - 2; i > 0; i--) {
      tmpTree[i] = mimc7_hasher.hash([tmpTree[i*2+1], tmpTree[2*(i+1)]], 0);
    }

    // Compute the merkle root
    tmpTree[0] = mimc7_hasher.hash([tmpTree[1], tmpTree[2]], 0);

    return tmpTree;
  }

  // Returns the root of the merkle tree
  function getRoot() public view returns(bytes32) {
    return getTree()[0];
  }
}
