// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_UTIL_API_TCC__
#define __ZETH_UTIL_API_TCC__

#include <libzeth/util_api.hpp>

namespace libzeth
{

template<typename FieldT> FieldT parse_merkle_node(std::string mk_node)
{
    return string_to_field<FieldT>(mk_node);
}

template<typename FieldT, size_t TreeDepth>
joinsplit_input<FieldT, TreeDepth> parse_joinsplit_input(
    const prover_proto::JoinsplitInput &input)
{
    if (TreeDepth != input.merkle_path_size()) {
        throw std::invalid_argument("Invalid merkle path length");
    }

    zeth_note input_note = parse_zeth_note(input.note());
    size_t inputAddress = input.address();
    bits_addr<TreeDepth> input_address_bits =
        get_bits_addr_from_vector<TreeDepth>(
            address_bits_from_address<TreeDepth>(inputAddress));
    bits256 input_spending_ask = hex_digest_to_bits256(input.spending_ask());
    bits256 input_nullifier = hex_digest_to_bits256(input.nullifier());

    std::vector<FieldT> input_merkle_path;
    for (size_t i = 0; i < TreeDepth; i++) {
        FieldT mk_node = parse_merkle_node<FieldT>(input.merkle_path(i));
        input_merkle_path.push_back(mk_node);
    }

    return joinsplit_input<FieldT, TreeDepth>(
        input_merkle_path,
        input_address_bits,
        input_note,
        input_spending_ask,
        input_nullifier);
}

template<typename ppT>
prover_proto::HexPointBaseGroup1Affine format_hexPointBaseGroup1Affine(
    const libff::G1<ppT> &point)
{
    libff::G1<ppT> aff = point;
    aff.to_affine_coordinates();
    std::string x_coord =
        "0x" + hex_from_libsnark_bigint<libff::Fq<ppT>>(aff.X.as_bigint());
    std::string y_coord =
        "0x" + hex_from_libsnark_bigint<libff::Fq<ppT>>(aff.Y.as_bigint());

    prover_proto::HexPointBaseGroup1Affine res;
    res.set_x_coord(x_coord);
    res.set_y_coord(y_coord);

    return res;
}

template<typename ppT>
prover_proto::HexPointBaseGroup2Affine format_hexPointBaseGroup2Affine(
    const libff::G2<ppT> &point)
{
    libff::G2<ppT> aff = point;
    aff.to_affine_coordinates();
    std::string x_c1_coord =
        "0x" + hex_from_libsnark_bigint<libff::Fq<ppT>>(aff.X.c1.as_bigint());
    std::string x_c0_coord =
        "0x" + hex_from_libsnark_bigint<libff::Fq<ppT>>(aff.X.c0.as_bigint());
    std::string y_c1_coord =
        "0x" + hex_from_libsnark_bigint<libff::Fq<ppT>>(aff.Y.c1.as_bigint());
    std::string y_c0_coord =
        "0x" + hex_from_libsnark_bigint<libff::Fq<ppT>>(aff.Y.c0.as_bigint());

    prover_proto::HexPointBaseGroup2Affine res;
    res.set_x_c0_coord(x_c0_coord);
    res.set_x_c1_coord(x_c1_coord);
    res.set_y_c0_coord(y_c0_coord);
    res.set_y_c1_coord(y_c1_coord);

    return res;
}

template<ppT>
std::string format_primary_inputs(std::vector<libff::Fr<ppT>> public_inputs)
{
    std::stringstream ss;
    ss << "[";
    for (size_t i = 0; i < public_inputs.size(); ++i) {
        ss << "0x"
           << libzeth::hex_from_libsnark_bigint<libff::Fr<ppT>>(
                  public_inputs[i].as_bigint());
        if (i < public_inputs.size() - 1) {
            ss << ", ";
        }
    }
    ss << "]";
    std::string inputs_json_str = ss.str();

    return inputs_json_str;
}

} // namespace libzeth

#endif // __ZETH_UTIL_API_TCC__
