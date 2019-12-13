// Copyright (c) 2015-2019 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_UTIL_API_TCC__
#define __ZETH_UTIL_API_TCC__

namespace libzeth
{

template<typename FieldT> FieldT parse_merkle_node(std::string mk_node)
{
    return string_to_field<FieldT>(mk_node);
}

template<typename FieldT>
joinsplit_input<FieldT> parse_joinsplit_input(
    const prover_proto::JoinsplitInput &input)
{
    if (ZETH_MERKLE_TREE_DEPTH != input.merkle_path_size()) {
        throw std::invalid_argument("Invalid merkle path length");
    }

    zeth_note input_note = parse_zeth_note(input.note());
    size_t inputAddress = input.address();
    bits_addr input_address_bits = get_bits_addr_from_vector(
        address_bits_from_address(inputAddress, ZETH_MERKLE_TREE_DEPTH));
    bits256 input_spending_ask = hex_digest_to_bits256(input.spending_ask());
    bits256 input_nullifier = hex_digest_to_bits256(input.nullifier());

    std::vector<FieldT> input_merkle_path;
    for (int i = 0; i < ZETH_MERKLE_TREE_DEPTH; i++) {
        FieldT mk_node = parse_merkle_node<FieldT>(input.merkle_path(i));
        input_merkle_path.push_back(mk_node);
    }

    return joinsplit_input<FieldT>(
        input_merkle_path,
        input_address_bits,
        input_note,
        input_spending_ask,
        input_nullifier);
}

} // namespace libzeth

#endif // __ZETH_UTIL_API_TCC__
