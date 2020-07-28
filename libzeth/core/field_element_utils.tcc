// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_FIELD_ELEMENT_UTILS_TCC__
#define __ZETH_FIELD_ELEMENT_UTILS_TCC__

#include "libzeth/core/field_element_utils.hpp"
#include "libzeth/core/utils.hpp"

#include <boost/assert.hpp>
#include <iomanip>

/// This file uses types and preprocessor variables defined in the `gmp.h`
/// header:
///  - `mp_size_t`
///  - `GMP_LIMB_BITS`
///  - `GMP_NAIL_BITS`

namespace libzeth
{

namespace internal
{

template<typename FieldT> class field_element_json
{
public:
    /// Convert a field element to JSON
    static void write(std::ostream &o, const FieldT &field_el)
    {
        // Note that we write components of extension fields
        // highest-order-first.
        o << '[';
        size_t i = FieldT::tower_extension_degree - 1;
        do {
            o << field_element_to_json(field_el.coeffs[i]);
            if (i > 0) {
                o << ',';
            }
        } while (i-- > 0);
        o << ']';
    }

    /// Read a field element from JSON
    static void read(std::istream &in, FieldT &field_el)
    {
        // Read opening '[' char, then each component (highest-order-first)
        // separated by ',' char, then a closing ']' char.

        char sep;
        in >> sep;
        if (sep != '[') {
            throw std::runtime_error("expected opening bracket");
        }

        size_t i = FieldT::tower_extension_degree - 1;
        do {
            field_element_read_json(in, field_el.coeffs[i]);
            if (i > 0) {
                in >> sep;
                if (sep != ',') {
                    throw std::runtime_error("expected comma separator");
                }
            }
        } while (i-- > 0);

        in >> sep;
        if (sep != ']') {
            throw std::runtime_error("expected closing bracket");
        }
    }
};

/// Implementation of field_element_json for the base-case of Fp_model
/// types.
template<mp_size_t n, const libff::bigint<n> &modulus>
class field_element_json<libff::Fp_model<n, modulus>>
{
public:
    using Field = libff::Fp_model<n, modulus>;
    static void write(std::ostream &o, const Field &field_el)
    {
        o << '"' << base_field_element_to_hex(field_el) << '"';
    };
    static void read(std::istream &i, Field &field_el)
    {
        char quote;
        i >> quote;
        if (quote != '"') {
            throw std::runtime_error("expected json string");
        }
        std::string bigint_hex;
        try {
            std::getline(i, bigint_hex, '"');
        } catch (...) {
            throw std::runtime_error("json string not terminated");
        }
        field_el = base_field_element_from_hex<Field>(bigint_hex);
    }
};

} // namespace internal

template<typename FieldT>
std::string bigint_to_hex(
    const libff::bigint<FieldT::num_limbs> &limbs, bool prefix)
{
    return bytes_to_hex_reversed(&limbs.data[0], sizeof(limbs.data), prefix);
}

template<typename FieldT>
libff::bigint<FieldT::num_limbs> bigint_from_hex(const std::string &hex)
{
    libff::bigint<FieldT::num_limbs> res;
    hex_to_bytes_reversed(hex, &res.data[0], sizeof(res.data));
    return res;
}

template<typename FieldT>
std::string base_field_element_to_hex(const FieldT &field_el)
{
    // Serialize a "ground/base" field element
    BOOST_ASSERT(FieldT::extension_degree() == 1);
    return bigint_to_hex<FieldT>(field_el.as_bigint(), true);
}

template<typename FieldT>
FieldT base_field_element_from_hex(const std::string &hex)
{
    return FieldT(bigint_from_hex<FieldT>(hex));
}

template<typename FieldT>
void field_element_write_json(std::ostream &out, const FieldT &el)
{
    internal::field_element_json<FieldT>::write(out, el);
}

template<typename FieldT>
void field_element_read_json(std::istream &in, FieldT &el)
{
    internal::field_element_json<FieldT>::read(in, el);
}

template<typename FieldT> std::string field_element_to_json(const FieldT &el)
{
    std::stringstream ss;
    ss.exceptions(
        std::ios_base::eofbit | std::ios_base::badbit | std::ios_base::failbit);
    field_element_write_json(ss, el);
    return ss.str();
}

template<typename FieldT>
FieldT field_element_from_json(const std::string &json)
{
    std::stringstream ss(json);
    FieldT result;
    field_element_read_json(ss, result);
    return result;
}

} // namespace libzeth

#endif // __ZETH_FIELD_ELEMENT_UTILS_TCC__
