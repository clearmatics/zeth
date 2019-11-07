#ifndef __ZETH_TYPES_JOINSPLIT_HPP__
#define __ZETH_TYPES_JOINSPLIT_HPP__

#include "types/bits.hpp"
#include "types/note.hpp"

#include <libsnark/common/data_structures/merkle_tree.hpp>
#include <vector>

namespace libzeth
{

// We simplify the interface of the joinsplit_input object compared to what Zcash did
// In fact, all our fields are going to be computed from another component
// written in python or js, that will use the ethereum primitives to hash.
template<typename FieldT> class joinsplit_input
{
public:
    // --- Merkle tree witness (path, and address)
    std::vector<FieldT> witness_merkle_path;
    bits_addr address_bits; // boolean vector of length the depth of the merkle
                           // tree containing the binary encoding of the address

    zeth_note note;
    bits256 spending_key_a_sk;
    bits256 nullifier;

    joinsplit_input(){};
    joinsplit_input(
        std::vector<FieldT> witness_merkle_path,
        bits_addr address_bits,
        zeth_note note,
        bits256 key,
        bits256 nullifier)
        : witness_merkle_path(witness_merkle_path)
        , address_bits(address_bits)
        , note(note)
        , spending_key_a_sk(key)
        , nullifier(nullifier)
    {
    }
};

} // namespace libzeth

#endif // __ZETH_TYPES_JOINSPLIT_HPP__