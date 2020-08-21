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
    libff::G1<ppT> aff = point;
    aff.to_affine_coordinates();

    zeth_proto::HexPointBaseGroup1Affine res;
    res.set_x_coord(field_element_to_json(aff.X));
    res.set_y_coord(field_element_to_json(aff.Y));
    return res;
}

template<typename ppT>
libff::G1<ppT> point_g1_affine_from_proto(
    const zeth_proto::HexPointBaseGroup1Affine &point)
{
    using Fq = libff::Fq<ppT>;
    Fq x_coordinate = field_element_from_json<Fq>(point.x_coord());
    Fq y_coordinate = field_element_from_json<Fq>(point.y_coord());
    return libff::G1<ppT>(x_coordinate, y_coordinate, Fq::one());
}

template<typename ppT>
zeth_proto::HexPointBaseGroup2Affine point_g2_affine_to_proto(
    const libff::G2<ppT> &point)
{
    assert(!point.is_zero());
    libff::G2<ppT> aff = point;
    aff.to_affine_coordinates();

    zeth_proto::HexPointBaseGroup2Affine res;
    res.set_x_coord(field_element_to_json(aff.X));
    res.set_y_coord(field_element_to_json(aff.Y));
    return res;
}

template<typename ppT>
libff::G2<ppT> point_g2_affine_from_proto(
    const zeth_proto::HexPointBaseGroup2Affine &point)
{
    using TwistField = typename libff::G2<ppT>::twist_field;
    const TwistField X = field_element_from_json<TwistField>(point.x_coord());
    const TwistField Y = field_element_from_json<TwistField>(point.y_coord());
    return libff::G2<ppT>(X, Y, TwistField::one());
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
        FieldT mk_node =
            base_field_element_from_hex<FieldT>(input.merkle_path(i));
        input_merkle_path.push_back(mk_node);
    }

    return joinsplit_input<FieldT, TreeDepth>(
        std::move(input_merkle_path),
        bits_addr<TreeDepth>::from_size_t(input.address()),
        zeth_note_from_proto(input.note()),
        bits256::from_hex(input.spending_ask()),
        bits256::from_hex(input.nullifier()));
}

} // namespace libzeth

#endif // __ZETH_SERIALIZATION_PROTO_UTILS_TCC__
