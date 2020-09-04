// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CORE_GROUP_ELEMENT_UTILS_TCC__
#define __ZETH_CORE_GROUP_ELEMENT_UTILS_TCC__

#include "libzeth/core/field_element_utils.hpp"

namespace libzeth
{

template<typename GroupT>
void point_affine_write_json(const GroupT &point, std::ostream &out_s)
{
    GroupT affine_p = point;
    affine_p.to_affine_coordinates();
    out_s << "[";
    field_element_write_json(affine_p.X, out_s);
    out_s << ",";
    field_element_write_json(affine_p.Y, out_s);
    out_s << "]";
}

template<typename GroupT>
void point_affine_read_json(GroupT &point, std::istream &in_s)
{
    char sep;

    in_s >> sep;
    if (sep != '[') {
        throw std::runtime_error(
            "expected opening bracket reading group element");
    }
    field_element_read_json(point.X, in_s);

    in_s >> sep;
    if (sep != ',') {
        throw std::runtime_error("expected comma reading group element");
    }

    field_element_read_json(point.Y, in_s);
    in_s >> sep;
    if (sep != ']') {
        throw std::runtime_error(
            "expected closing bracket reading group element");
    }

    point.Z = point.Z.one();
}

template<typename GroupT> std::string point_affine_to_json(const GroupT &point)
{
    std::stringstream ss;
    point_affine_write_json(point, ss);
    return ss.str();
}

template<typename GroupT> GroupT point_affine_from_json(const std::string &json)
{
    std::stringstream ss(json);
    GroupT result;
    point_affine_read_json(result, ss);
    return result;
}

} // namespace libzeth

#endif // __ZETH_CORE_GROUP_ELEMENT_UTILS_TCC__
