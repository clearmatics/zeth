// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_FIELD_ELEMENT_UTILS_TCC__
#define __ZETH_FIELD_ELEMENT_UTILS_TCC__

#include "libzeth/core/field_element_utils.hpp"
#include "libzeth/core/utils.hpp"

#include <assert.h>
#include <iomanip>

namespace libzeth
{

template<typename FieldT>
std::string base_field_element_to_hex(const FieldT &field_el)
{
    static_assert(
        FieldT::extension_degree() == 1, "only valid on base/ground fields");
    return libff::bigint_to_hex(field_el.as_bigint(), true);
}

template<typename FieldT>
FieldT base_field_element_from_hex(const std::string &hex)
{
    static_assert(
        FieldT::extension_degree() == 1, "only valid on base/ground fields");
    using BigIntT =
        typename std::decay<decltype(((FieldT *)nullptr)->mont_repr)>::type;
    BigIntT v;
    libff::bigint_from_hex(v, hex);
    return FieldT(v);
}

template<typename FieldT>
void field_element_write_json(const FieldT &el, std::ostream &out_s)
{
    libff::field_write<libff::encoding_json, libff::form_plain>(el, out_s);
}

template<typename FieldT>
void field_element_read_json(FieldT &el, std::istream &in_s)
{
    libff::field_read<libff::encoding_json, libff::form_plain>(el, in_s);
}

template<typename FieldT> std::string field_element_to_json(const FieldT &el)
{
    std::stringstream ss;
    ss.exceptions(
        std::ios_base::eofbit | std::ios_base::badbit | std::ios_base::failbit);
    field_element_write_json(el, ss);
    return ss.str();
}

template<typename FieldT>
FieldT field_element_from_json(const std::string &json)
{
    std::stringstream ss(json);
    FieldT result;
    field_element_read_json(result, ss);
    return result;
}

template<typename FieldT>
void field_element_write_bytes(const FieldT &el, std::ostream &out_s)
{
    libff::field_write<libff::encoding_binary, libff::form_plain>(el, out_s);
}

template<typename FieldT>
void field_element_read_bytes(FieldT &el, std::istream &in_s)
{
    libff::field_read<libff::encoding_binary, libff::form_plain>(el, in_s);
}

} // namespace libzeth

#endif // __ZETH_FIELD_ELEMENT_UTILS_TCC__
