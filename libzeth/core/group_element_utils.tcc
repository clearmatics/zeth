// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CORE_GROUP_ELEMENT_UTILS_TCC__
#define __ZETH_CORE_GROUP_ELEMENT_UTILS_TCC__

#include "libzeth/core/field_element_utils.hpp"

namespace libzeth
{

template<typename ppT>
std::string point_g1_affine_to_hex(const libff::G1<ppT> &point)
{
    libff::G1<ppT> affine_p = point;
    affine_p.to_affine_coordinates();
    return "\"0x" + bigint_to_hex<libff::Fq<ppT>>(affine_p.X.as_bigint()) +
           "\", \"0x" + bigint_to_hex<libff::Fq<ppT>>(affine_p.Y.as_bigint()) +
           "\"";
}

template<typename ppT>
std::string point_g2_affine_to_hex(const libff::G2<ppT> &point)
{
    libff::G2<ppT> affine_p = point;
    affine_p.to_affine_coordinates();
    return "[\"0x" + bigint_to_hex<libff::Fq<ppT>>(affine_p.X.c1.as_bigint()) +
           "\", \"0x" +
           bigint_to_hex<libff::Fq<ppT>>(affine_p.X.c0.as_bigint()) +
           "\"],\n [\"0x" +
           bigint_to_hex<libff::Fq<ppT>>(affine_p.Y.c1.as_bigint()) +
           "\", \"0x" +
           bigint_to_hex<libff::Fq<ppT>>(affine_p.Y.c0.as_bigint()) + "\"]";
}

} // namespace libzeth

#endif // __ZETH_CORE_GROUP_ELEMENT_UTILS_TCC__
