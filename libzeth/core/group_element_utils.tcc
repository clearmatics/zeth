// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CORE_GROUP_ELEMENT_UTILS_TCC__
#define __ZETH_CORE_GROUP_ELEMENT_UTILS_TCC__

#include "libzeth/core/field_element_utils.hpp"

namespace libzeth
{

template<typename GroupT, typename FieldT>
std::string point_affine_to_json(const GroupT &point)
{
    GroupT affine_p = point;
    affine_p.to_affine_coordinates();

    std::stringstream ss;
    ss << "[";
    field_element_json<FieldT>::write(ss, affine_p.X);
    ss << ",";
    field_element_json<FieldT>::write(ss, affine_p.Y);
    ss << "]";

    return ss.str();
}

template<typename GroupT, typename FieldT>
GroupT point_affine_from_json(const std::string &json)
{
    GroupT result;
    char sep;

    std::stringstream ss(json);
    ss >> sep;
    if (sep != '[') {
        throw std::runtime_error(
            "expected opening bracket reading group element");
    }
    field_element_json<FieldT>::read(ss, result.X);

    ss >> sep;
    if (sep != ',') {
        throw std::runtime_error("expected comma reading group element");
    }

    field_element_json<FieldT>::read(ss, result.Y);
    ss >> sep;
    if (sep != '[') {
        throw std::runtime_error(
            "expected closing bracket reading group element");
    }

    result.Z = FieldT::one();
    return result;
}

template<typename ppT>
std::string point_g1_affine_to_json(const libff::G1<ppT> &point)
{
    return point_affine_to_json<
        libff::G1<ppT>,
        typename libff::G1<ppT>::base_field>(point);

    // libff::G1<ppT> affine_p = point;
    // affine_p.to_affine_coordinates();
    // return "[\"0x" + base_field_element_to_hex<libff::Fq<ppT>>(affine_p.X) +
    //        "\", \"0x" + base_field_element_to_hex<libff::Fq<ppT>>(affine_p.Y)
    //        +
    //        "\"]";
}

template<typename ppT>
libff::G1<ppT> point_g1_affine_from_json(const std::string &grp_str)
{
    return point_affine_from_json<
        libff::G1<ppT>,
        typename libff::G1<ppT>::base_field>(grp_str);
}

template<typename ppT>
std::string point_g2_affine_to_json(const libff::G2<ppT> &point)
{
    return point_affine_to_json<
        libff::G2<ppT>,
        typename libff::G2<ppT>::twist_field>(point);

    // libff::G2<ppT> affine_p = point;
    // affine_p.to_affine_coordinates();
    // const std::string x_coord = field_element_to_json(affine_p.X);
    // const std::string y_coord = field_element_to_json(affine_p.Y);

    // return "[" + x_coord + "," + y_coord + "]";

    // const std::vector<std::string> x_coord =
    //     ext_field_element_to_hex<libff::Fqe<ppT>>(affine_p.X);
    // const std::vector<std::string> y_coord =
    //     ext_field_element_to_hex<libff::Fqe<ppT>>(affine_p.Y);
    // const size_t extension_degree = libff::Fqe<ppT>::extension_degree();
    // BOOST_ASSERT(extension_degree >= 2);

    // std::stringstream ss;
    // // Write the coordinates in reverse order to match the previous
    // // implementation
    // ss << "[\n[\"0x" << x_coord[extension_degree - 1];
    // for (size_t i = extension_degree - 1; i >= 1; --i) {
    //     ss << "\", \"0x" << x_coord[i - 1];
    // }
    // ss << "\"],\n[\"0x" << y_coord[extension_degree - 1];
    // for (size_t i = extension_degree - 1; i >= 1; --i) {
    //     ss << "\", \"0x" << y_coord[i - 1];
    // }
    // ss << "\"]\n]";

    // return ss.str();
}

} // namespace libzeth

#endif // __ZETH_CORE_GROUP_ELEMENT_UTILS_TCC__
