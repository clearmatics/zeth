// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/mpc/groth16/powersoftau_utils.hpp"

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/fields/fp2.hpp>

namespace libzeth
{

namespace
{

// Utility functions

class membuf : public std::streambuf
{
public:
    membuf(char *begin, char *end) { this->setg(begin, begin, end); }
};

// template<mp_size_t n, const libff::bigint<n> &modulus>
// void to_montgomery_repr(libff::Fp_model<n, modulus> &m)
// {
//     m.mul_reduce(libff::Fp_model<n, modulus>::Rsquared);
// }

// template<mp_size_t n, const libff::bigint<n> &modulus>
// libff::Fp_model<n, modulus> from_montgomery_repr(libff::Fp_model<n, modulus>
// m)
// {
//     libff::Fp_model<n, modulus> tmp;
//     tmp.mont_repr.data[0] = 1;
//     tmp.mul_reduce(m.mont_repr);
//     return tmp;
// }

// template<mp_size_t n, const libff::bigint<n> &modulus>
// std::istream &read_powersoftau_fp(
//     std::istream &in, libff::Fp_model<n, modulus> &out)
// {
//     const size_t data_size = sizeof(libff::bigint<n>);
//     char *bytes = (char *)&out;
//     in.read(bytes, data_size);

//     std::reverse(&bytes[0], &bytes[data_size]);
//     to_montgomery_repr(out);

//     return in;
// }

// template<mp_size_t n, const libff::bigint<n> &modulus>
// void write_powersoftau_fp(
//     std::ostream &out, const libff::Fp_model<n, modulus> &fp)
// {
//     libff::Fp_model<n, modulus> copy = from_montgomery_repr(fp);
//     std::reverse((char *)&copy, (char *)(&copy + 1));
//     out.write((const char *)&copy, sizeof(mp_limb_t) * n);
// }

// template<mp_size_t n, const libff::bigint<n> &modulus>
// std::istream &read_powersoftau_fp2(
//     std::istream &in, libff::Fp2_model<n, modulus> &el)
// {
//     // Fq2 data is packed into a single 512 bit integer as:
//     //
//     //   c1 * modulus + c0
//     libff::bigint<2 * n> packed;
//     in >> packed;
//     std::reverse((uint8_t *)&packed, (uint8_t *)((&packed) + 1));

//     libff::bigint<n + 1> c1;

//     mpn_tdiv_qr(
//         c1.data,              // quotient
//         el.c0.mont_repr.data, // remainder
//         0,
//         packed.data,
//         n * 2,
//         modulus.data,
//         n);

//     for (size_t i = 0; i < n; ++i) {
//         el.c1.mont_repr.data[i] = c1.data[i];
//     }

//     to_montgomery_repr(el.c0);
//     to_montgomery_repr(el.c1);

//     return in;
// }

// template<mp_size_t n, const libff::bigint<n> &modulus>
// void write_powersoftau_fp2(
//     std::ostream &out, const libff::Fp2_model<n, modulus> &fp2)
// {
//     // Fq2 data is packed into a single 512 bit integer as:
//     //
//     //   c1 * modulus + c0
//     libff::Fp_model<n, modulus> c0 = from_montgomery_repr(fp2.c0);
//     libff::Fp_model<n, modulus> c1 = from_montgomery_repr(fp2.c1);

//     libff::bigint<2 * n> packed;
//     packed.clear();
//     for (size_t i = 0; i < n; ++i) {
//         packed.data[i] = c0.mont_repr.data[i];
//     }

//     for (size_t i = 0; i < n; ++i) {
//         mp_limb_t carryout = mpn_addmul_1(
//             &packed.data[i], modulus.data, n, c1.mont_repr.data[i]);
//         assert(packed.data[n + i] == 0);
//         carryout = mpn_add_1(
//             &packed.data[n + i], &packed.data[n + i], n - i, carryout);
//         assert(carryout == 0);
//     }

//     std::reverse((uint8_t *)&packed, (uint8_t *)((&packed) + 1));
//     out.write((const char *)&packed, sizeof(packed));
// }

} // namespace

// template<>
// void read_powersoftau_fr<libff::alt_bn128_pp>(
//     std::istream &in, libff::alt_bn128_Fr &out)
// {
//     read_powersoftau_fp(in, out);
// }

// template<>
// void read_powersoftau_g1<libff::alt_bn128_pp>(
//     std::istream &in, libff::alt_bn128_G1 &out)
// {
//     uint8_t marker;
//     in.read((char *)&marker, 1);

//     switch (marker) {
//     case 0x00:
//         // zero
//         out = libff::alt_bn128_G1::zero();
//         break;
//     case 0x04: {
//         // Uncompressed
//         libff::alt_bn128_Fq x;
//         libff::alt_bn128_Fq y;
//         read_powersoftau_fp(in, x);
//         read_powersoftau_fp(in, y);
//         out = libff::alt_bn128_G1(x, y, libff::alt_bn128_Fq::one());
//         break;
//     }
//     default:
//         assert(false);
//         break;
//     }
// }

// void read_powersoftau_fq2(std::istream &in, libff::alt_bn128_Fq2 &out)
// {
//     read_powersoftau_fp2(in, out);
// }

// template<>
// void read_powersoftau_g2<libff::alt_bn128_pp>(
//     std::istream &in, libff::alt_bn128_G2 &out)
// {
//     uint8_t marker;
//     in.read((char *)&marker, 1);

//     switch (marker) {
//     case 0x00:
//         // zero
//         out = libff::alt_bn128_G2::zero();
//         break;

//     case 0x04:
//         // Uncompressed
//         read_powersoftau_fp2(in, out.X);
//         read_powersoftau_fp2(in, out.Y);
//         out.Z = libff::alt_bn128_Fq2::one();
//         break;

//     default:
//         assert(false);
//         break;
//     }
// }

// template<>
// void write_powersoftau_fr<libff::alt_bn128_pp>(
//     std::ostream &out, const libff::alt_bn128_Fr &fr)
// {
//     write_powersoftau_fp(out, fr);
// }

// void write_powersoftau_fq2(std::ostream &out, const libff::alt_bn128_Fq2 &fq2)
// {
//     write_powersoftau_fp2(out, fq2);
// }

// template<>
// void write_powersoftau_g1<libff::alt_bn128_pp>(
//     std::ostream &out, const libff::alt_bn128_G1 &g1)
// {
//     if (g1.is_zero()) {
//         const uint8_t zero = 0;
//         out.write((const char *)&zero, 1);
//         return;
//     }

//     libff::alt_bn128_G1 copy(g1);
//     copy.to_affine_coordinates();

//     const uint8_t marker = 0x04;
//     out.write((const char *)&marker, 1);
//     write_powersoftau_fp(out, copy.X);
//     write_powersoftau_fp(out, copy.Y);
// }

// template<>
// void write_powersoftau_g2<libff::alt_bn128_pp>(
//     std::ostream &out, const libff::alt_bn128_G2 &g2)
// {
//     if (g2.is_zero()) {
//         const uint8_t zero = 0;
//         out.write((const char *)&zero, 1);
//         return;
//     }

//     libff::alt_bn128_G2 copy(g2);
//     copy.to_affine_coordinates();

//     const uint8_t marker = 0x04;
//     out.write((const char *)&marker, 1);
//     write_powersoftau_fp2(out, copy.X);
//     write_powersoftau_fp2(out, copy.Y);
// }

} // namespace libzeth
