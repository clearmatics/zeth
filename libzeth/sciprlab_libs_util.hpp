// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SCIPRLAB_LIBS_UTIL_HPP__
#define __ZETH_SCIPRLAB_LIBS_UTIL_HPP__

#include "libzeth/util.hpp"

#include <boost/filesystem.hpp>
#include <cassert>
#include <libff/common/default_types/ec_pp.hpp>
#include <stdbool.h>
#include <stdint.h>

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

/// Convert a group element of G1 to an hexadecimal string.
/// This function assumes that the group element is in affine
/// form, and that both coordinates (X, Y) are elements of a
/// prime field.
template<typename ppT>
std::string point_g1_affine_to_hexadecimal_str(const libff::G1<ppT> &point);

/// Convert a group element of G2 to an hexadecimal string.
/// This function assumes that the group element is in affine
/// form, and that both coordinates (X, Y) are elements of a
/// an extension field of degree 2.
template<typename ppT>
std::string point_g2_affine_to_hexadecimal_str(const libff::G2<ppT> &point);

} // namespace libzeth
#include "libzeth/sciprlab_libs_util.tcc"

#endif // __ZETH_SCIPRLAB_LIBS_UTIL_HPP__
