// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CORE_JOINSPLIT_HPP__
#define __ZETH_CORE_JOINSPLIT_HPP__

#include "libzeth/core/bits.hpp"
#include "libzeth/core/note.hpp"

#include <libsnark/common/data_structures/merkle_tree.hpp>
#include <vector>

namespace libzeth
{

// We simplify the interface of the joinsplit_input object compared to what
// Zcash did. In fact, all our fields are going to be computed from another
// component written in python or js, that will use the ethereum primitives to
// hash.
template<typename FieldT, size_t TreeDepth> class joinsplit_input
{
public:
    // merkle tree witness (path, and address)
    std::vector<FieldT> witness_merkle_path;
    // boolean vector, of length the depth of the merkle tree, containing the
    // binary encoding of the address
    bits_addr<TreeDepth> address_bits;
    zeth_note note;
    bits256 spending_key_a_sk;
    bits256 nullifier;

    joinsplit_input(){};
    joinsplit_input(
        std::vector<FieldT> witness_merkle_path,
        std::array<bool, TreeDepth> address_bits,
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

#endif // __ZETH_CORE_JOINSPLIT_HPP__
