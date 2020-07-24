// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CORE_GROUP_ELEMENT_UTILS_HPP__
#define __ZETH_CORE_GROUP_ELEMENT_UTILS_HPP__

#include "include_libff.hpp"

namespace libzeth
{

/// Convert a group element to a json string (array of hexadecimal strings).
template<typename GroupT> std::string point_affine_to_json(const GroupT &point);

/// Convert a JSON string into a group element
template<typename GroupT>
GroupT point_affine_from_json(const std::string &json);

} // namespace libzeth

#include "libzeth/core/group_element_utils.tcc"

#endif // __ZETH_CORE_GROUP_ELEMENT_UTILS_HPP__
