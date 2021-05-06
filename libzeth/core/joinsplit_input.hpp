// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CORE_JOINSPLIT_INPUT_HPP__
#define __ZETH_CORE_JOINSPLIT_INPUT_HPP__

#include "libzeth/core/bits.hpp"
#include "libzeth/core/note.hpp"

#include <libsnark/common/data_structures/merkle_tree.hpp>
#include <vector>

namespace libzeth
{

/// We simplify the interface of the joinsplit_input object compared to what
/// Zcash did. In fact, all our fields are going to be computed from another
/// component written in Python or JS, that will use the Ethereum primitives
/// to hash.
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
        std::vector<FieldT> &&witness_merkle_path,
        const bits_addr<TreeDepth> &address_bits,
        const zeth_note &note,
        const bits256 &key,
        const bits256 &nullifier)
        : witness_merkle_path(std::move(witness_merkle_path))
        , address_bits(address_bits)
        , note(note)
        , spending_key_a_sk(key)
        , nullifier(nullifier)
    {
    }
};

} // namespace libzeth

#endif // __ZETH_CORE_JOINSPLIT_INPUT_HPP__
