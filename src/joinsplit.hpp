#ifndef __ZETH_JOINSPLIT_HP__
#define __ZETH_JOINSPLIT_HP__

// We simplify the interface of the JSInput object compared to what Zcash did
// In fact, all our fields are going to be computed from another component
// written in python or js, that will use the ethereum primitives to hash.
class JSInput {
public:
    // --- Merkle tree witness (path, and address)
    std::vector<merkle_authentication_node> witness_merkle_path;
    size_t address,
    libff::bit_vector address_bits,

    ZethNote note;
    uint256 spending_key_a_sk;
    uint256 nullifier;

    JSInput();
    JSInput(std::vector<merkle_authentication_node> witness_merkle_path,
            ZethNote note,
            uint256 key,
            uint256 nullifier) : witness_merkle_path(witness_merkle_path), note(note), spending_key_a_sk(key), nullifier(nullifier){}
};

#endif