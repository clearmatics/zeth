// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CORE_FIELD_ELEMENT_UTILS_HPP__
#define __ZETH_CORE_FIELD_ELEMENT_UTILS_HPP__

#include "include_libff.hpp"

namespace libzeth
{
/// Convert a base field element (single component) to a hexadecimal
/// string (without any JSON decoration such as '"').
template<typename FieldT>
std::string base_field_element_to_hex(const FieldT &field_el);

/// Convert a plain hex string (without any JSON decoration such as '"') to a
/// base field element (single component).
template<typename FieldT>
FieldT base_field_element_from_hex(const std::string &field_str);

template<typename FieldT>
void field_element_write_json(const FieldT &el, std::ostream &out_s);

template<typename FieldT>
void field_element_read_json(FieldT &el, std::istream &in_s);

template<typename FieldT> std::string field_element_to_json(const FieldT &el);

template<typename FieldT>
FieldT field_element_from_json(const std::string &json);

/// Write a field element as bytes. Base field elements are written in plain
/// (non-Montgomery) form as fixed-size big-endian integers. Extension field
/// elements are written as a series of components.
template<typename FieldT>
void field_element_write_bytes(const FieldT &el, std::ostream &out_s);

/// Read a field element as bytes, in the format described for
/// field_element_write_bytes.
template<typename FieldT>
void field_element_read_bytes(FieldT &el, std::istream &in_s);

} // namespace libzeth

#include "libzeth/core/field_element_utils.tcc"

#endif // __ZETH_CORE_FIELD_ELEMENT_UTILS_HPP__
