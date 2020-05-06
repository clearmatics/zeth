// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_FIELD_ELEMENT_UTILS_TCC__
#define __ZETH_FIELD_ELEMENT_UTILS_TCC__

#include "libzeth/core/field_element_utils.hpp"
#include "libzeth/core/utils.hpp"

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
std::string field_element_to_hex(const FieldT &field_el)
{
    return bigint_to_hex<FieldT>(field_el.as_bigint());
}

template<typename FieldT> FieldT field_element_from_hex(const std::string &hex)
{
    return FieldT(bigint_from_hex<FieldT>(hex));
}

} // namespace libzeth

#endif // __ZETH_FIELD_ELEMENT_UTILS_TCC__
