// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SERIALIZATION_PROTO_UTILS_TCC__
#define __ZETH_SERIALIZATION_PROTO_UTILS_TCC__

#include "libzeth/serialization/proto_utils.hpp"

#include <cassert>

namespace libzeth
{

template<typename ppT>
zeth_proto::HexPointBaseGroup1Affine point_g1_affine_to_proto(
    const libff::G1<ppT> &point)
{
    assert(!point.is_zero());
    using Fq = libff::Fq<ppT>;
    libff::G1<ppT> aff = point;
    aff.to_affine_coordinates();

    zeth_proto::HexPointBaseGroup1Affine res;
    res.set_x_coord("0x" + field_element_to_hex<Fq>(aff.X));
    res.set_y_coord("0x" + field_element_to_hex<Fq>(aff.Y));
    return res;
}

template<typename ppT>
libff::G1<ppT> point_g1_affine_from_proto(
    const zeth_proto::HexPointBaseGroup1Affine &point)
{
    using Fq = libff::Fq<ppT>;

    Fq x_coordinate = field_element_from_hex<Fq>(point.x_coord());
    Fq y_coordinate = field_element_from_hex<Fq>(point.y_coord());
    return libff::G1<ppT>(x_coordinate, y_coordinate, Fq::one());
}

template<typename ppT>
zeth_proto::HexPointBaseGroup2Affine point_g2_affine_to_proto(
    const libff::G2<ppT> &point)
{
    assert(!point.is_zero());
    using Fq = libff::Fq<ppT>;
    libff::G2<ppT> aff = point;
    aff.to_affine_coordinates();

    zeth_proto::HexPointBaseGroup2Affine res;
    res.set_x_c0_coord("0x" + field_element_to_hex<Fq>(aff.X.c0));
    res.set_x_c1_coord("0x" + field_element_to_hex<Fq>(aff.X.c1));
    res.set_y_c0_coord("0x" + field_element_to_hex<Fq>(aff.Y.c0));
    res.set_y_c1_coord("0x" + field_element_to_hex<Fq>(aff.Y.c1));

    return res;
}

template<typename ppT>
libff::G2<ppT> point_g2_affine_from_proto(
    const zeth_proto::HexPointBaseGroup2Affine &point)
{
    using Fq = libff::Fq<ppT>;
    using Fqe = libff::Fqe<ppT>;

    // See:
    // https://github.com/scipr-lab/libff/blob/master/libff/algebra/curves/public_params.hpp#L88
    // and:
    // https://github.com/scipr-lab/libff/blob/master/libff/algebra/curves/mnt/mnt4/mnt4_pp.hpp#L33
    //
    // As such, each element of Fqe is assumed to be a vector of 2 coefficients
    // lying in the base field

    Fq x_c0 = field_element_from_hex<Fq>(point.x_c0_coord());
    Fq x_c1 = field_element_from_hex<Fq>(point.x_c1_coord());
    Fq y_c0 = field_element_from_hex<Fq>(point.y_c0_coord());
    Fq y_c1 = field_element_from_hex<Fq>(point.y_c1_coord());
    return libff::G2<ppT>(Fqe(x_c0, x_c1), Fqe(y_c0, y_c1), Fqe::one());
}

template<typename FieldT, size_t TreeDepth>
joinsplit_input<FieldT, TreeDepth> joinsplit_input_from_proto(
    const zeth_proto::JoinsplitInput &input)
{
    if (TreeDepth != input.merkle_path_size()) {
        throw std::invalid_argument("Invalid merkle path length");
    }

    std::vector<FieldT> input_merkle_path;
    for (size_t i = 0; i < TreeDepth; i++) {
        FieldT mk_node = field_element_from_hex<FieldT>(input.merkle_path(i));
        input_merkle_path.push_back(mk_node);
    }

    return joinsplit_input<FieldT, TreeDepth>(
        input_merkle_path,
        bits_addr_from_size_t<TreeDepth>(input.address()),
        zeth_note_from_proto(input.note()),
        bits256_from_hex(input.spending_ask()),
        bits256_from_hex(input.nullifier()));
}

template<typename ppT>
std::string primary_inputs_to_string(
    const std::vector<libff::Fr<ppT>> &public_inputs)
{
    std::stringstream ss;
    ss << "[";
    for (size_t i = 0; i < public_inputs.size(); ++i) {
        ss << "\"0x"
           << libzeth::bigint_to_hex<libff::Fr<ppT>>(
                  public_inputs[i].as_bigint())
           << "\"";
        if (i < public_inputs.size() - 1) {
            ss << ", ";
        }
    }
    ss << "]";
    std::string inputs_json_str = ss.str();

    return inputs_json_str;
}

template<typename ppT>
std::vector<libff::Fr<ppT>> primary_inputs_from_string(
    const std::string &input_str)
{
    std::vector<libff::Fr<ppT>> res;
    size_t next_hex_pos = input_str.find("0x");
    while (next_hex_pos != std::string::npos) {
        // TODO: avoid the string copy here
        const size_t end_hex = input_str.find("\"", next_hex_pos);
        const std::string next_hex =
            input_str.substr(next_hex_pos, end_hex - next_hex_pos);
        res.push_back(field_element_from_hex<libff::Fr<ppT>>(next_hex));
        next_hex_pos = input_str.find("0x", end_hex);
    }
    return res;
}

template<typename ppT>
std::string accumulation_vector_to_string(
    const libsnark::accumulation_vector<libff::G1<ppT>> &acc_vector)
{
    std::stringstream ss;
    unsigned vect_length = acc_vector.rest.indices.size() + 1;
    ss << "[" << point_g1_affine_to_json<ppT>(acc_vector.first);
    for (size_t i = 0; i < vect_length - 1; ++i) {
        ss << ", "
           << point_g1_affine_to_json<ppT>(acc_vector.rest.values[i]);
    }
    ss << "]";
    std::string vect_json_str = ss.str();

    return vect_json_str;
}

template<typename ppT>
libsnark::accumulation_vector<libff::G1<ppT>> accumulation_vector_from_string(
    const std::string &acc_vector_str)
{
    std::string prefix = std::string("[[\"");
    std::string suffix = std::string("\"]]");
    if (acc_vector_str.length() < prefix.length()) {
        throw std::invalid_argument("invalid accumulation vector string");
    }

    if ((acc_vector_str.find(prefix) != 0) || 
        (acc_vector_str.compare(acc_vector_str.length() - suffix.length(),
            suffix.length(), suffix) != 0))
    {
        throw std::invalid_argument("invalid accumulation vector string");
    }

    // Erase the outer '[' and ']'
    std::string acc_vector_str_bis = acc_vector_str.substr(1, acc_vector_str.size() - 2);

    // Retrieve all 1 dimensional arrays of strings. They represent G1 elements
    // since we assume that el_g1 = [x, y], where (x,y) \in (\F_p)^2, p prime
    std::vector<libff::G1<ppT>> res;
    size_t next_el_pos = acc_vector_str_bis.find("[");
    while (next_el_pos != std::string::npos) {
        const size_t end_el = acc_vector_str_bis.find("]", next_el_pos);
        const std::string element_str =
            acc_vector_str_bis.substr(next_el_pos, end_el - next_el_pos);
        std::cout << "element_str: " << element_str << std::endl;
        res.push_back(point_g1_affine_from_json<ppT>(element_str));
        next_el_pos = acc_vector_str_bis.find("[", end_el);
    }

    libsnark::accumulation_vector<libff::G1<ppT>> acc_res;
    acc_res.first = res.front();
    res.erase(res.begin());
    acc_res.rest = libsnark::sparse_vector<libff::G1<ppT>>(std::move(res));

    return acc_res;
}

} // namespace libzeth

#endif // __ZETH_SERIALIZATION_PROTO_UTILS_TCC__
