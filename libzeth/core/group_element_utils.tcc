// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CORE_GROUP_ELEMENT_UTILS_TCC__
#define __ZETH_CORE_GROUP_ELEMENT_UTILS_TCC__

#include "libzeth/core/field_element_utils.hpp"

namespace libzeth
{

template<typename ppT>
std::string point_g1_affine_to_json(const libff::G1<ppT> &point)
{
    libff::G1<ppT> affine_p = point;
    affine_p.to_affine_coordinates();
    return "[\"0x" + bigint_to_hex<libff::Fq<ppT>>(affine_p.X.as_bigint()) +
           "\", \"0x" + bigint_to_hex<libff::Fq<ppT>>(affine_p.Y.as_bigint()) +
           "\"]";
}

template<typename ppT>
libff::G1<ppT> point_g1_affine_from_json(const std::string &grp_str)
{
    std::vector<libff::Fq<ppT>> coordinates;
    size_t next_hex_pos = grp_str.find("0x");
    while (next_hex_pos != std::string::npos) {
        const size_t end_hex = grp_str.find("\"", next_hex_pos);
        const std::string next_hex =
            grp_str.substr(next_hex_pos, end_hex - next_hex_pos);
        coordinates.push_back(field_element_from_hex<libff::Fq<ppT>>(next_hex));
        next_hex_pos = grp_str.find("0x", end_hex);
    }

    // Points in affine form are expected
    if (coordinates.size() > 2) {
        throw std::invalid_argument("invalid number of coordinates");
    }

    return libff::G1<ppT>(
        coordinates[0], coordinates[1], libff::Fq<ppT>::one());
}

template<typename ppT>
std::string point_g2_affine_to_json(const libff::G2<ppT> &point)
{
    libff::G2<ppT> affine_p = point;
    affine_p.to_affine_coordinates();
    return "[\n"
           "[\"0x" +
           bigint_to_hex<libff::Fq<ppT>>(affine_p.X.c1.as_bigint()) +
           "\", \"0x" +
           bigint_to_hex<libff::Fq<ppT>>(affine_p.X.c0.as_bigint()) +
           "\"],\n"
           "[\"0x" +
           bigint_to_hex<libff::Fq<ppT>>(affine_p.Y.c1.as_bigint()) +
           "\", \"0x" +
           bigint_to_hex<libff::Fq<ppT>>(affine_p.Y.c0.as_bigint()) +
           "\"]\n"
           "]";
}

} // namespace libzeth

#endif // __ZETH_CORE_GROUP_ELEMENT_UTILS_TCC__
