// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CORE_GROUP_ELEMENT_UTILS_HPP__
#define __ZETH_CORE_GROUP_ELEMENT_UTILS_HPP__

#include "include_libff.hpp"

namespace libzeth
{

/// Write a group element as a json string to a stream
template<typename GroupT>
void group_element_write_json(const GroupT &point, std::ostream &out_s);

/// Read a JSON string from a stream and convert it into a group element
template<typename GroupT>
void group_element_read_json(GroupT &point, std::istream &in_s);

/// Convert a group element to a json string (array of hexadecimal strings).
template<typename GroupT>
std::string group_element_to_json(const GroupT &point);

/// Convert a JSON string into a group element
template<typename GroupT>
GroupT group_element_from_json(const std::string &json);

} // namespace libzeth

#include "libzeth/core/group_element_utils.tcc"

#endif // __ZETH_CORE_GROUP_ELEMENT_UTILS_HPP__
