pragma solidity ^0.5.0;

// Adapted from: https://github.com/zcash-hackworks/babyzoe

import "./MiMC7.sol";

contract MerkleTreeMiMCHash {
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
            tmpTree[i] = MiMCHash([tmpTree[i*2+1], tmpTree[2*(i+1)]], 0);
        }

        // Compute the merkle root
        tmpTree[0] = MiMCHash([tmpTree[1], tmpTree[2]], 0);

        return tmpTree;
    }

    // Returns the root of the merkle tree
    function getRoot() public view returns(bytes32) {
        return getTree()[0];
    }

    function MiMCHash(bytes32[2] memory x, bytes32 iv) public pure returns (bytes32 h_p) {
        uint p = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        bytes32 x_c; //current input;
        bytes32 seed = keccak256("mimc");
        h_p = iv; //previous hash

        for( uint i = 0; i < x.length; i++ ) {
            x_c = x[i];

          assembly {
              let c := mload(0x40)
              mstore(0x40, add(c, 32))
              mstore(c, seed)

              let h_c:= x_c
              for {let j := 0} slt(j, 91) {j := add(j,1)} {
                  mstore(c, keccak256(c, 32))
                  let a :=  addmod(addmod(h_c, mload(c), p), h_p, p)
                  let b := mulmod(a, a, p)
                  h_c :=  mulmod(mulmod(mulmod(b,b,p),b,p),a,p)
              }
              //NB: merged last round of the permutation with Myjaguchi-Prenell step
              h_p := addmod(addmod(addmod(h_c , h_p, p), x_c, p), h_p, p)
          }
        }
    }
}
