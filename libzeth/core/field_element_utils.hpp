// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CORE_FIELD_ELEMENT_UTILS_HPP__
#define __ZETH_CORE_FIELD_ELEMENT_UTILS_HPP__

#include "include_libff.hpp"

namespace libzeth
{

/// WARNING: The following function assumes that NAILS are NOT used
/// See Section 8.2 (page 68): https://gmplib.org/gmp-man-6.2.0.pdf
/// In other words, we assume below that:
///  - GMP_NUMB_BITS = GMP_LIMB_BITS and thus,
///  - GMP_NAIL_BITS = 0
///
/// This function decomposes a bigint into an array of bytes.
///
/// For instance, if the number of bits in a Limb is 64,
/// and we have `input_bigint = [Limb0, Limb1, Limb2, Limb3]`,
/// where every Limb{i} is of type `mp_limb_t`, then the function returns
///
///  x = [x0, ..., x7, x8, ..., x15, x16, ..., x23, x24, ..., x31]
///        ^       ^    ^        ^    ^         ^    ^         ^
///        |_______|    |________|    |_________|    |_________|
///            |            |              |              |
///          Limb3        Limb2          Limb1          Limb0
///
/// where all x_i's are bytes (uint8_t)
template<typename FieldT>
std::string libsnark_bigint_to_hexadecimal_str(
    const libff::bigint<FieldT::num_limbs> &limbs);

/// WARNING: The following function assumes that NAILS are NOT used
/// See Section 8.2 (page 68): https://gmplib.org/gmp-man-6.2.0.pdf
/// In other words, we assume below that:
///  - GMP_NUMB_BITS = GMP_LIMB_BITS and thus,
///  - GMP_NAIL_BITS = 0
///
/// This function recomposes a bigint from an array of bytes.
///
/// For instance, if the number of bits in a Limb is 64, and we have as input:
///  x = [x0, ..., x7, x8, ..., x15, x16, ..., x23, x24, ..., x31]
///        ^       ^    ^        ^    ^         ^    ^         ^
///        |_______|    |________|    |_________|    |_________|
///            |            |              |              |
///          Limb3        Limb2          Limb1          Limb0
/// where all x_i's are bytes (uint8_t)
///
/// then the function returns:
/// and we have `res_bigint = [Limb0, Limb1, Limb2, Limb3]`,
/// where every Limb{i} is of type `mp_limb_t`,
template<typename FieldT>
libff::bigint<FieldT::num_limbs> bytes_to_libsnark_bigint(
    const uint8_t bytes[(FieldT::num_bits + 8 - 1) / 8]);

/// Convert an hexadecimal string to a field element
template<typename FieldT>
FieldT hexadecimal_str_to_field_element(std::string field_str);

/// Convert a field element to an hexadecimal string
template<typename FieldT>
std::string field_element_to_hexadecimal_str(FieldT field_el);

} // namespace libzeth

#include "libzeth/core/field_element_utils.tcc"

#endif // __ZETH_CORE_FIELD_ELEMENT_UTILS_HPP__
