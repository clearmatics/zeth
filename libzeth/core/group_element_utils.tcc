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
    return "[\"0x" + base_field_element_to_hex<libff::Fq<ppT>>(affine_p.X) +
           "\", \"0x" + base_field_element_to_hex<libff::Fq<ppT>>(affine_p.Y) +
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
        coordinates.push_back(
            base_field_element_from_hex<libff::Fq<ppT>>(next_hex));
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
    const std::vector<std::string> x_coord =
        ext_field_element_to_hex<libff::Fqe<ppT>>(affine_p.X);
    const std::vector<std::string> y_coord =
        ext_field_element_to_hex<libff::Fqe<ppT>>(affine_p.Y);

    const size_t extension_degree = libff::Fqe<ppT>::extension_degree();
    BOOST_ASSERT(extension_degree >= 2);

    std::stringstream ss;
    // Write the coordinates in reverse order to match the previous
    // implementation
    ss << "[\n[\"0x" << x_coord[extension_degree - 1];
    for (size_t i = extension_degree - 1; i >= 1; --i) {
        ss << "\", \"0x" << x_coord[i - 1];
    }
    ss << "\"],\n[\"0x" << y_coord[extension_degree - 1];
    for (size_t i = extension_degree - 1; i >= 1; --i) {
        ss << "\", \"0x" << y_coord[i - 1];
    }
    ss << "\"]\n]";

    return ss.str();
}

} // namespace libzeth

#endif // __ZETH_CORE_GROUP_ELEMENT_UTILS_TCC__
