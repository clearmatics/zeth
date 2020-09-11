// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CORE_GROUP_ELEMENT_UTILS_TCC__
#define __ZETH_CORE_GROUP_ELEMENT_UTILS_TCC__

#include "libzeth/core/field_element_utils.hpp"

namespace libzeth
{

template<typename GroupT> std::string point_affine_to_json(const GroupT &point)
{
    GroupT affine_p = point;
    affine_p.to_affine_coordinates();

    std::stringstream ss;
    ss << "[";
    field_element_write_json(affine_p.X, ss);
    ss << ",";
    field_element_write_json(affine_p.Y, ss);
    ss << "]";

    return ss.str();
}

template<typename GroupT> GroupT point_affine_from_json(const std::string &json)
{
    GroupT result;
    char sep;

    std::stringstream ss(json);
    ss >> sep;
    if (sep != '[') {
        throw std::runtime_error(
            "expected opening bracket reading group element");
    }
    field_element_read_json(result.X, ss);

    ss >> sep;
    if (sep != ',') {
        throw std::runtime_error("expected comma reading group element");
    }

    field_element_read_json(result.Y, ss);
    ss >> sep;
    if (sep != ']') {
        throw std::runtime_error(
            "expected closing bracket reading group element");
    }

    result.Z = result.Z.one();
    return result;
}

} // namespace libzeth

#endif // __ZETH_CORE_GROUP_ELEMENT_UTILS_TCC__
