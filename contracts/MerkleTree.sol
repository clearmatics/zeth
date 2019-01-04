pragma solidity ^0.4.24;

// Adapted from: https://github.com/zcash-hackworks/babyzoe

contract MerkleTreeSha256 {
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

    // Constructor
    constructor(uint treeDepth, uint digestLen, address hashContractAddr) {
        depth = treeDepth;
        nbLeaves = 2**depth;

        // Initialize the merkle tree with zeroes in values
        for (uint i = 0; i < nbLeaves; i++) {
            leaves.push(bytes("0x0"));
        }
    }

    // Appends a commitment to the tree, and returns its address
    function insert(bytes32 commitment) internal returns (uint) {
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
    function getLeaves() constant public returns (bytes32[] memory) { // returns the bytes32[] array of leaves
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
    function getTree() public returns (bytes32[] memory) {
        uint nbNodes = 2**(depth + 1) - 1;
        bytes32[] memory tmpTree = new bytes32[](nbNodes);

        // Dump the leaves in the right indexes in the tree
        for (uint i = 0; i < nbLeaves; i++) {
            tmpTree[(nbLeaves - 1) + i] = leaves[i];
        }

        // Compute the internal nodes of the merkle tree
        for (uint i = nbLeaves - 2; i >= 0; i--) {
            tree[i] = sha256(tmpTree[i*2+1], tmpTree[2*(i+1)]);
        }

        return tmpTree;
    }

    // Returns the root of the merkle tree
    function getRoot() constant returns(bytes32 memory) {
        return getTree()[0];
    }
}
