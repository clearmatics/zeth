// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_DEBUG_HELPERS_TCC__
#define __ZETH_DEBUG_HELPERS_TCC__

#include <fstream>
#include <iomanip>
#include <iostream>
#include <libff/algebra/fields/bigint.hpp>
#include <libff/common/default_types/ec_pp.hpp>
#include <sstream>

// This file uses types and preprocessor variables defined in the `gmp.h`
// header:
//  - `mp_size_t`
//  - `GMP_LIMB_BITS`
//  - `GMP_NAIL_BITS`

namespace libzeth
{

// WARNING: The following function assumes that NAILS are NOT used
// See Section 8.2 (page 68): https://gmplib.org/gmp-man-6.2.0.pdf
// In other words, we assume below that:
//  - GMP_NUMB_BITS = GMP_LIMB_BITS and thus,
//  - GMP_NAIL_BITS = 0
//
// This function decomposes a bigint into an array of bytes.
//
// For instance, if the number of bits in a Limb is 64,
// and we have `input_bigint = [Limb0, Limb1, Limb2, Limb3]`,
// where every Limb{i} is of type `mp_limb_t`, then the function returns
//
//  x = [x0, ..., x7, x8, ..., x15, x16, ..., x23, x24, ..., x31]
//        ^       ^    ^        ^    ^         ^    ^         ^
//        |_______|    |________|    |_________|    |_________|
//            |            |              |              |
//          Limb3        Limb2          Limb1          Limb0
//
// where all x_i's are bytes (uint8_t)
template<typename FieldT>
std::string hex_from_libsnark_bigint(
    const libff::bigint<FieldT::num_limbs> &limbs)
{
    const unsigned bytes_per_limb = (GMP_LIMB_BITS + 8 - 1) / 8;

    uint8_t x[bytes_per_limb * FieldT::num_limbs];
    for (unsigned i = 0; i < FieldT::num_limbs; i++) {
        for (unsigned j = 0; j < bytes_per_limb; j++) {
            x[i * 8 + j] = uint8_t(
                uint64_t(limbs.data[(FieldT::num_limbs - 1) - i]) >>
                (GMP_LIMB_BITS - 8 * (j + 1)));
        }
    }

    std::stringstream ss;

    // Display every byte as 2 hexadecimal characters
    ss << std::setfill('0');
    for (unsigned i = 0; i < bytes_per_limb * FieldT::num_limbs; i++) {
        ss << std::hex << std::setw(2) << (int)x[i];
    }
    std::string str = ss.str();

    // Remove leading 0's
    return str.erase(0, std::min(str.find_first_not_of('0'), str.size() - 1));
}

// WARNING: The following function assumes that NAILS are NOT used
// See Section 8.2 (page 68): https://gmplib.org/gmp-man-6.2.0.pdf
// In other words, we assume below that:
//  - GMP_NUMB_BITS = GMP_LIMB_BITS and thus,
//  - GMP_NAIL_BITS = 0
//
// This function recomposes a bigint from an array of bytes.
//
// For instance, if the number of bits in a Limb is 64, and we have as input:
//  x = [x0, ..., x7, x8, ..., x15, x16, ..., x23, x24, ..., x31]
//        ^       ^    ^        ^    ^         ^    ^         ^
//        |_______|    |________|    |_________|    |_________|
//            |            |              |              |
//          Limb3        Limb2          Limb1          Limb0
// where all x_i's are bytes (uint8_t)
//
// then the function returns:
// and we have `res_bigint = [Limb0, Limb1, Limb2, Limb3]`,
// where every Limb{i} is of type `mp_limb_t`,
template<typename FieldT>
libff::bigint<FieldT::num_limbs> libsnark_bigint_from_bytes(
    const uint8_t bytes[((GMP_LIMB_BITS + 8 - 1) / 8) * FieldT::num_limbs])
{
    const unsigned bytes_per_limb = (GMP_LIMB_BITS + 8 - 1) / 8;

    libff::bigint<FieldT::num_limbs> res;

    for (unsigned i = 0; i < FieldT::num_limbs; i++) {
        for (unsigned j = 0; j < bytes_per_limb; j++) {
            res.data[FieldT::num_limbs - i - 1] |=
                mp_limb_t(bytes[i * 8 + j]) << (GMP_LIMB_BITS - 8 * (j + 1));
        }
    }
    return res;
}

template<typename ppT>
std::string point_g1_affine_as_hex(const libff::G1<ppT> &point)
{
    libff::G1<ppT> affine_p = point;
    affine_p.to_affine_coordinates();
    return "\"0x" +
           hex_from_libsnark_bigint<libff::Fq<ppT>>(affine_p.X.as_bigint()) +
           "\", \"0x" +
           hex_from_libsnark_bigint<libff::Fq<ppT>>(affine_p.Y.as_bigint()) +
           "\"";
}

template<typename ppT>
std::string point_g2_affine_as_hex(const libff::G2<ppT> &point)
{
    libff::G2<ppT> affine_p = point;
    affine_p.to_affine_coordinates();
    return "[\"0x" +
           hex_from_libsnark_bigint<libff::Fq<ppT>>(affine_p.X.c1.as_bigint()) +
           "\", \"0x" +
           hex_from_libsnark_bigint<libff::Fq<ppT>>(affine_p.X.c0.as_bigint()) +
           "\"],\n [\"0x" +
           hex_from_libsnark_bigint<libff::Fq<ppT>>(affine_p.Y.c1.as_bigint()) +
           "\", \"0x" +
           hex_from_libsnark_bigint<libff::Fq<ppT>>(affine_p.Y.c0.as_bigint()) +
           "\"]";
}

} // namespace libzeth

#endif // __ZETH_DEBUG_HELPERS_TCC__
