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

template<typename FieldT>
std::string bigint_to_hex(const libff::bigint<FieldT::num_limbs> &limbs)
{
    return bytes_to_hex_reversed(&limbs.data[0], sizeof(limbs.data));
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
    return bigint_to_hex<FieldT>(field_el.as_bigint());
}

template<typename FieldT>
FieldT base_field_element_from_hex(const std::string &hex)
{
    return FieldT(bigint_from_hex<FieldT>(hex));
}

template<typename EFieldT>
std::vector<std::string> ext_field_element_to_hex(const EFieldT &field_el)
{
    const size_t extension_degree = EFieldT::extension_degree();

    // Make sure we process an extension field element
    BOOST_ASSERT(extension_degree > 1);
    // Make sure we process a "non-towered" extension field element
    BOOST_ASSERT(extension_degree == EFieldT::tower_extension_degree);

    std::vector<std::string> res;
    for (size_t i = 0; i < extension_degree; i++) {
        res.push_back(bigint_to_hex<typename EFieldT::my_Fp>(
            field_el.coeffs[i].as_bigint()));
    }

    return res;
}

template<typename EFieldT>
EFieldT ext_field_element_from_hex(const std::vector<std::string> &hex_vec)
{
    const size_t extension_degree = EFieldT::extension_degree();

    // Make sure we process an extension field element
    BOOST_ASSERT(extension_degree > 1);
    // Make sure we process a "non-towered" extension field element
    BOOST_ASSERT(extension_degree == EFieldT::tower_extension_degree);
    // Make sure we process an input in the right form
    BOOST_ASSERT(extension_degree == hex_vec.size());

    typename EFieldT::my_Fp tmp[extension_degree];
    for (size_t i = 0; i < extension_degree; i++) {
        tmp[i] =
            base_field_element_from_hex<typename EFieldT::my_Fp>(hex_vec[i]);
    }

    // TODO: Add constructor from array in libff to avoid to extra copy step
    // that would be cleaner.
    EFieldT el = EFieldT();
    std::copy(std::begin(tmp), std::end(tmp), std::begin(el.coeffs));
    return el;
}

} // namespace libzeth

#endif // __ZETH_FIELD_ELEMENT_UTILS_TCC__
