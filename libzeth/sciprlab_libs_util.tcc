// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SCIPRLAB_LIBS_UTIL_TCC__
#define __ZETH_SCIPRLAB_LIBS_UTIL_TCC__

#include <fstream>
#include <iomanip>
#include <iostream>
#include <libff/algebra/fields/bigint.hpp>
#include <libff/common/default_types/ec_pp.hpp>
#include <sstream>

/// This file uses types and preprocessor variables defined in the `gmp.h`
/// header:
///  - `mp_size_t`
///  - `GMP_LIMB_BITS`
///  - `GMP_NAIL_BITS`

namespace libzeth
{

template<typename FieldT>
std::string libsnark_bigint_to_hexadecimal_str(
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

    return str;
}

template<typename FieldT>
libff::bigint<FieldT::num_limbs> bytes_to_libsnark_bigint(
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

template<typename FieldT>
FieldT hexadecimal_str_to_field_element(std::string field_str)
{
    // Remove prefix if any
    erase_substring(field_str, std::string("0x"));

    // 1 byte will be populated by 2 hexadecimal characters
    uint8_t val[field_str.size() / 2];

    char cstr[field_str.size() + 1];
    strcpy(cstr, field_str.c_str());

    int res = hexadecimal_str_to_byte_array(cstr, val);
    if (res == 0) {
        throw std::invalid_argument("Invalid hexadecimal string");
    }

    libff::bigint<FieldT::num_limbs> el =
        bytes_to_libsnark_bigint<FieldT>(val);
    return FieldT(el);
}

template<typename FieldT>
std::string field_element_to_hexadecimal_str(FieldT field_el)
{
    return libsnark_bigint_to_hexadecimal_str(field_el.as_bigint());
}

template<typename ppT>
std::string point_g1_affine_to_hexadecimal_str(const libff::G1<ppT> &point)
{
    libff::G1<ppT> affine_p = point;
    affine_p.to_affine_coordinates();
    return "\"0x" +
           libsnark_bigint_to_hexadecimal_str<libff::Fq<ppT>>(affine_p.X.as_bigint()) +
           "\", \"0x" +
           libsnark_bigint_to_hexadecimal_str<libff::Fq<ppT>>(affine_p.Y.as_bigint()) +
           "\"";
}

template<typename ppT>
std::string point_g2_affine_to_hexadecimal_str(const libff::G2<ppT> &point)
{
    libff::G2<ppT> affine_p = point;
    affine_p.to_affine_coordinates();
    return "[\"0x" +
           libsnark_bigint_to_hexadecimal_str<libff::Fq<ppT>>(affine_p.X.c1.as_bigint()) +
           "\", \"0x" +
           libsnark_bigint_to_hexadecimal_str<libff::Fq<ppT>>(affine_p.X.c0.as_bigint()) +
           "\"],\n [\"0x" +
           libsnark_bigint_to_hexadecimal_str<libff::Fq<ppT>>(affine_p.Y.c1.as_bigint()) +
           "\", \"0x" +
           libsnark_bigint_to_hexadecimal_str<libff::Fq<ppT>>(affine_p.Y.c0.as_bigint()) +
           "\"]";
}

} // namespace libzeth

#endif // __ZETH_SCIPRLAB_LIBS_UTIL_TCC__
