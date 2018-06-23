// https://github.com/zcash-hackworks/babyzoe

contract MerkleTree {
    struct Mtree {
        uint currentNode; // Index of the current node where to insert the next incoming commitment
        bytes32[16] leaves; // Array containing the 16 leaves of the merkle tree of commitments
    }

    Mtree public MT;
    
    // Constructor
    function MerkleTree() {
        // This initialization should not be required in theory:
        // TODO: To remove
        for (uint i = 0; i < 16; i++) {
            MT.leaves[i] = 0x0; // Initialization of all the leaves to the zero value 0x0
        }
    }

    // Appends a commitment to the tree
    function insert(bytes32 commitment) internal returns (bool res) {
        if (MT.currentNode == 16) {
            return false; // All the leaves contain a commitment => The tree is "full"
        }

        MT.leaves[MT.currentNode] = commitment;
        MT.currentNode++;
        return true; // Insertion sucessful
    }

    function getSha256(bytes32 input, bytes32 sk) constant returns ( bytes32) { 
        return(sha256(input , sk)); 
    } 

    function getLeaves() constant returns (bytes32[16]) {
        return MT.leaves; // Returns the array of leaves of the merkle tree
    }

    function getTree() constant returns (bytes32[32] tree) {
        //bytes32[32] memory tree;

        bytes32 test = 0;
        uint i;
        for (i = 0; i < 16; i++) {
            tree[16 + i] = MT.leaves[i];
        }
        for (i = 16 - 1; i > 0; i--) {
            tree[i] = sha256(tree[i*2], tree[i*2+1]); 
        }
        return tree;
    }

    // Returns the root of the merkle tree
    function getRoot() constant returns(bytes32 root) {
        root = getTree()[1];
    }

}
