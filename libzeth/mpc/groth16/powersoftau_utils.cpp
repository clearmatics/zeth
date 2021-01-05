// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/mpc/groth16/powersoftau_utils.hpp"

#include <libff/algebra/fields/fp2.hpp>

namespace libzeth
{

template<>
void read_powersoftau_g2<libff::alt_bn128_pp>(
    std::istream &in, libff::alt_bn128_G2 &out)
{
    uint8_t marker;
    in.read((char *)&marker, 1);

    switch (marker) {
    case 0x00:
        // zero
        out = libff::alt_bn128_G2::zero();
        break;

    case 0x04:
        // Uncompressed
        read_powersoftau_fp2(in, out.X);
        read_powersoftau_fp2(in, out.Y);
        out.Z = libff::alt_bn128_Fq2::one();
        break;

    default:
        assert(false);
        break;
    }
}

template<>
void write_powersoftau_g2<libff::alt_bn128_pp>(
    std::ostream &out, const libff::alt_bn128_G2 &g2)
{
    if (g2.is_zero()) {
        const uint8_t zero = 0;
        out.write((const char *)&zero, 1);
        return;
    }

    libff::alt_bn128_G2 copy(g2);
    copy.to_affine_coordinates();

    const uint8_t marker = 0x04;
    out.write((const char *)&marker, 1);
    write_powersoftau_fp2(out, copy.X);
    write_powersoftau_fp2(out, copy.Y);
}

} // namespace libzeth
