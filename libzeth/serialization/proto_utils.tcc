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
        std::move(input_merkle_path),
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
libsnark::accumulation_vector<libff::G1<ppT>> accumulation_vector_from_string(
    const std::string &acc_vector_str)
{
    // TODO: Copied from old code. Can be cleaned up significantly to not
    // allocate and copy strings. May be worth introducing composible parsing
    // functions, or switch to a real json library, to support more reuse.

    char *cstr = new char[acc_vector_str.length() + 1];
    std::strcpy(cstr, acc_vector_str.c_str());
    char *pos;
    printf("Splitting string \"%s\" into tokens:\n", cstr);

    std::vector<std::string> res;
    pos = strtok(cstr, "[, ]");

    while (pos != NULL) {
        res.push_back(std::string(pos));
        pos = strtok(NULL, "[, ]");
    }

    // Free heap memory allocated with the `new` above
    delete[] cstr;

    // Each element of G1 has 2 coordinates (the points are in the affine form)
    //
    // Messy check that the size of the vector resulting from the string parsing
    // is of the form 2*n meaning that it contains the x and y coordinates of n
    // points
    if (res.size() > 0 && res.size() % 2 != 0) {
        // TODO: Do exception throwing/catching properly
        std::cerr
            << "accumulation_vector_from_string: Wrong number of coordinates"
            << std::endl;
        exit(1);
    }

    libsnark::accumulation_vector<libff::G1<ppT>> acc_res;
    libff::Fq<ppT> x_coordinate = field_element_to_hex<libff::Fq<ppT>>(res[0]);
    libff::Fq<ppT> y_coordinate = field_element_to_hex<libff::Fq<ppT>>(res[1]);

    libff::G1<ppT> first_point_g1 = libff::G1<ppT>(x_coordinate, y_coordinate);
    acc_res.first = first_point_g1;

    // Set the `rest` of the accumulation vector
    libsnark::sparse_vector<libff::G1<ppT>> rest;
    libff::G1<ppT> point_g1;
    for (size_t i = 2; i < res.size(); i += 2) {
        // TODO:
        // This is BAD => this code is a duplicate of the function
        // `field_element_to_hex` Let's re-use the content of the
        // function `field_element_to_hex` here. To do this properly
        // this means that we need to modify the type of `abc_g1` in the proto
        // file to be a repeated G1 element (and not a string) Likewise for the
        // inputs which should be changed to repeated field elements
        libff::Fq<ppT> x_coord = field_element_to_hex<libff::Fq<ppT>>(res[i]);
        libff::Fq<ppT> y_coord =
            field_element_to_hex<libff::Fq<ppT>>(res[i + 1]);

        point_g1 = libff::G1<ppT>(x_coord, y_coord);
        rest[i / 2 - 1] = point_g1;
    }

    acc_res.rest = rest;
    return acc_res;
}

} // namespace libzeth

#endif // __ZETH_SERIALIZATION_PROTO_UTILS_TCC__
