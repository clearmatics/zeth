// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CORE_GROUP_ELEMENT_UTILS_TCC__
#define __ZETH_CORE_GROUP_ELEMENT_UTILS_TCC__

#include "libzeth/core/field_element_utils.hpp"
#include "libzeth/serialization/stream_utils.hpp"

namespace libzeth
{

namespace internal
{

// Wrapper around == FieldT::one() which can be used by the code below when the
// field type is not in scope.
template<typename FieldT> static bool coordinate_equals_zero(const FieldT &f)
{
    return f == FieldT::zero();
}

// Wrapper around == FieldT::one() which can be used by the code below when the
// field type is not in scope.
template<typename FieldT> static bool coordinate_equals_one(const FieldT &f)
{
    return f == FieldT::one();
}

} // namespace internal

template<typename GroupT>
void group_element_write_json(const GroupT &point, std::ostream &out_s)
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
void group_element_read_json(GroupT &point, std::istream &in_s)
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

    if (internal::coordinate_equals_zero(point.X) &&
        internal::coordinate_equals_one(point.Y)) {
        point.Z = point.Z.zero();
    } else {
        point.Z = point.Z.one();
    }
}

template<typename GroupT> std::string group_element_to_json(const GroupT &point)
{
    std::stringstream ss;
    group_element_write_json(point, ss);
    return ss.str();
}

template<typename GroupT>
GroupT group_element_from_json(const std::string &json)
{
    std::stringstream ss(json);
    GroupT result;
    group_element_read_json(result, ss);
    return result;
}

template<typename GroupT>
void group_element_write_bytes(const GroupT &point, std::ostream &out_s)
{
    typename std::decay<GroupT>::type affine_p = point;
    affine_p.to_affine_coordinates();
    field_element_write_bytes(affine_p.X, out_s);
    field_element_write_bytes(affine_p.Y, out_s);
}

template<typename GroupT>
void group_element_read_bytes(GroupT &point, std::istream &in_s)
{
    field_element_read_bytes(point.X, in_s);
    field_element_read_bytes(point.Y, in_s);
    if (internal::coordinate_equals_zero(point.X) &&
        internal::coordinate_equals_one(point.Y)) {
        point.Z = point.Z.zero();
    } else {
        point.Z = point.Z.one();
    }
}

template<typename GroupCollectionT>
void group_elements_write_bytes(
    const GroupCollectionT &points, std::ostream &out_s)
{
    collection_write_bytes<GroupCollectionT, group_element_write_bytes>(
        points, out_s);
}

template<typename GroupCollectionT>
void group_elements_read_bytes(GroupCollectionT &points, std::istream &in_s)
{
    collection_read_bytes<GroupCollectionT, group_element_read_bytes>(
        points, in_s);
}

} // namespace libzeth

#endif // __ZETH_CORE_GROUP_ELEMENT_UTILS_TCC__
