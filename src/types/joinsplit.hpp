#ifndef __ZETH_JOINSPLIT_HPP__
#define __ZETH_JOINSPLIT_HPP__

#include <vector>
#include <libsnark/common/data_structures/merkle_tree.hpp>
#include <src/types/merkle_tree.hpp>

#include "types/note.hpp"
#include "types/bits.hpp"

namespace libzeth {

typedef libff::default_ec_pp ppT;
typedef libff::Fr<ppT> FieldT;
typedef FieldT merkle_authentication_node;


// We simplify the interface of the JSInput object compared to what Zcash did
// In fact, all our fields are going to be computed from another component
// written in python or js, that will use the ethereum primitives to hash.
/*
class JSInput {
public:
    // --- Merkle tree witness (path, and address)
    std::vector<libsnark::merkle_authentication_node> witness_merkle_path;
    size_t address;
    bitsAddr address_bits; // boolean vector of length the depth of the merkle tree containing the binary encoding of the address

    ZethNote note;
    bits256 spending_key_a_sk;
    bits256 nullifier;

    JSInput(){};
    JSInput(
        std::vector<libsnark::merkle_authentication_node> witness_merkle_path,
        size_t address,
        bitsAddr address_bits,
        ZethNote note,
        bits256 key,
        bits256 nullifier
    ) : witness_merkle_path(witness_merkle_path), address(address), address_bits(address_bits), note(note), spending_key_a_sk(key), nullifier(nullifier){}
};
*/

class FJSInput {
public:
    // --- Merkle tree witness (path, and address)
    std::vector<merkle_authentication_node> witness_merkle_path;
    size_t address;
    bitsAddr address_bits; // boolean vector of length the depth of the merkle tree containing the binary encoding of the address

    FZethNote<FieldT> note;
    FieldT spending_key_a_sk;
    FieldT nullifier;

    FJSInput(){};
    FJSInput(
        std::vector<merkle_authentication_node> witness_merkle_path,
        size_t address,
        bitsAddr address_bits,
        FZethNote<FieldT> note,
        FieldT key,
        FieldT nullifier
    ) : witness_merkle_path(witness_merkle_path), address(address), address_bits(address_bits), note(note), spending_key_a_sk(key), nullifier(nullifier){}
};

} // libzeth

#endif // __ZETH_JOINSPLIT_HPP__