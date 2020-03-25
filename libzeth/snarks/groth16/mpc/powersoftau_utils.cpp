// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include <libzeth/snarks/groth16/mpc/powersoftau_utils.hpp>

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

template<mp_size_t n, const libff::bigint<n> &modulus>
void to_montgomery_repr(libff::Fp_model<n, modulus> &m)
{
    m.mul_reduce(libff::Fp_model<n, modulus>::Rsquared);
}

template<mp_size_t n, const libff::bigint<n> &modulus>
libff::Fp_model<n, modulus> from_montgomery_repr(libff::Fp_model<n, modulus> m)
{
    libff::Fp_model<n, modulus> tmp;
    tmp.mont_repr.data[0] = 1;
    tmp.mul_reduce(m.mont_repr);
    return tmp;
}

template<mp_size_t n, const libff::bigint<n> &modulus>
std::istream &read_powersoftau_fp(
    std::istream &in, libff::Fp_model<n, modulus> &out)
{
    const size_t data_size = sizeof(libff::bigint<n>);
    char *bytes = (char *)&out;
    in.read(bytes, data_size);

    std::reverse(&bytes[0], &bytes[data_size]);
    to_montgomery_repr(out);

    return in;
}

template<mp_size_t n, const libff::bigint<n> &modulus>
void write_powersoftau_fp(
    std::ostream &out, const libff::Fp_model<n, modulus> &fp)
{
    libff::Fp_model<n, modulus> copy = from_montgomery_repr(fp);
    std::reverse((char *)&copy, (char *)(&copy + 1));
    out.write((const char *)&copy, sizeof(mp_limb_t) * n);
}

template<mp_size_t n, const libff::bigint<n> &modulus>
std::istream &read_powersoftau_fp2(
    std::istream &in, libff::Fp2_model<n, modulus> &el)
{
    // Fq2 data is packed into a single 512 bit integer as:
    //
    //   c1 * modulus + c0
    libff::bigint<2 * n> packed;
    in >> packed;
    std::reverse((uint8_t *)&packed, (uint8_t *)((&packed) + 1));

    libff::bigint<n + 1> c1;

    mpn_tdiv_qr(
        c1.data,              // quotient
        el.c0.mont_repr.data, // remainder
        0,
        packed.data,
        n * 2,
        modulus.data,
        n);

    for (size_t i = 0; i < n; ++i) {
        el.c1.mont_repr.data[i] = c1.data[i];
    }

    to_montgomery_repr(el.c0);
    to_montgomery_repr(el.c1);

    return in;
}

template<mp_size_t n, const libff::bigint<n> &modulus>
void write_powersoftau_fp2(
    std::ostream &out, const libff::Fp2_model<n, modulus> &fp2)
{
    // Fq2 data is packed into a single 512 bit integer as:
    //
    //   c1 * modulus + c0
    libff::Fp_model<n, modulus> c0 = from_montgomery_repr(fp2.c0);
    libff::Fp_model<n, modulus> c1 = from_montgomery_repr(fp2.c1);

    libff::bigint<2 * n> packed;
    packed.clear();
    for (size_t i = 0; i < n; ++i) {
        packed.data[i] = c0.mont_repr.data[i];
    }

    for (size_t i = 0; i < n; ++i) {
        mp_limb_t carryout = mpn_addmul_1(
            &packed.data[i], modulus.data, n, c1.mont_repr.data[i]);
        assert(packed.data[n + i] == 0);
        carryout = mpn_add_1(
            &packed.data[n + i], &packed.data[n + i], n - i, carryout);
        assert(carryout == 0);
    }

    std::reverse((uint8_t *)&packed, (uint8_t *)((&packed) + 1));
    out.write((const char *)&packed, sizeof(packed));
}

} // namespace

// Functions below are only implemented for the alt_bn128 curve type.
using ppT = libff::alt_bn128_pp;

void read_powersoftau_fr(std::istream &in, libff::Fr<ppT> &out)
{
    read_powersoftau_fp(in, out);
}

void read_powersoftau_g1(std::istream &in, libff::G1<ppT> &out)
{
    uint8_t marker;
    in.read((char *)&marker, 1);

    switch (marker) {
    case 0x00:
        // zero
        out = libff::G1<ppT>::zero();
        break;
    case 0x04: {
        // Uncompressed
        libff::Fq<ppT> x;
        libff::Fq<ppT> y;
        read_powersoftau_fp(in, x);
        read_powersoftau_fp(in, y);
        out = libff::G1<ppT>(x, y, libff::Fq<ppT>::one());
        break;
    }
    default:
        assert(false);
        break;
    }
}

void read_powersoftau_fq2(std::istream &in, libff::alt_bn128_Fq2 &out)
{
    read_powersoftau_fp2(in, out);
}

void read_powersoftau_g2(std::istream &in, libff::G2<ppT> &out)
{
    uint8_t marker;
    in.read((char *)&marker, 1);

    switch (marker) {
    case 0x00:
        // zero
        out = libff::G2<ppT>::zero();
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

void write_powersoftau_fr(std::ostream &out, const libff::Fr<ppT> &fr)
{
    write_powersoftau_fp(out, fr);
}

void write_powersoftau_fq2(std::ostream &out, const libff::alt_bn128_Fq2 &fq2)
{
    write_powersoftau_fp2(out, fq2);
}

void write_powersoftau_g1(std::ostream &out, const libff::G1<ppT> &g1)
{
    if (g1.is_zero()) {
        const uint8_t zero = 0;
        out.write((const char *)&zero, 1);
        return;
    }

    libff::alt_bn128_G1 copy(g1);
    copy.to_affine_coordinates();

    const uint8_t marker = 0x04;
    out.write((const char *)&marker, 1);
    write_powersoftau_fp(out, copy.X);
    write_powersoftau_fp(out, copy.Y);
}

void write_powersoftau_g2(std::ostream &out, const libff::G2<ppT> &g2)
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

srs_powersoftau<ppT> powersoftau_load(std::istream &in, size_t n)
{
    using G1 = libff::G1<ppT>;
    using G2 = libff::G2<ppT>;

    // From:
    //
    //   https://github.com/clearmatics/powersoftau
    //
    // Assume the stream is the final challenge file from the
    // powersoftau protocol.  Load the Accumulator object.
    //
    // File is structured:
    //
    //   [prev_resp_hash : uint8_t[64]]
    //   [accumulator    : Accumulator]
    //
    // From src/lib.rs:
    //
    //   pub struct Accumulator {
    //     /// tau^0, tau^1, tau^2, ..., tau^{TAU_POWERS_G1_LENGTH - 1}
    //     pub tau_powers_g1: Vec<G1>,
    //     /// tau^0, tau^1, tau^2, ..., tau^{TAU_POWERS_LENGTH - 1}
    //     pub tau_powers_g2: Vec<G2>,
    //     /// alpha * tau^0, alpha * tau^1, alpha * tau^2, ..., alpha *
    //     tau^{TAU_POWERS_LENGTH - 1} pub alpha_tau_powers_g1: Vec<G1>,
    //     /// beta * tau^0, beta * tau^1, beta * tau^2, ..., beta *
    //     tau^{TAU_POWERS_LENGTH - 1} pub beta_tau_powers_g1: Vec<G1>,
    //     /// beta
    //     pub beta_g2: G2
    //   }
    uint8_t hash[64];
    in.read((char *)(&hash[0]), sizeof(hash));

    const size_t num_powers_of_tau = 2 * n - 1;

    std::vector<G1> tau_powers_g1(num_powers_of_tau);
    for (size_t i = 0; i < num_powers_of_tau; ++i) {
        read_powersoftau_g1(in, tau_powers_g1[i]);
    }
    if (tau_powers_g1[0] != G1::one()) {
        throw std::invalid_argument("invalid powersoftau file?");
    }

    std::vector<G2> tau_powers_g2(n);
    for (size_t i = 0; i < n; ++i) {
        read_powersoftau_g2(in, tau_powers_g2[i]);
    }
    if (tau_powers_g2[0] != G2::one()) {
        throw std::invalid_argument("invalid powersoftau file?");
    }

    std::vector<G1> alpha_tau_powers_g1(n);
    for (size_t i = 0; i < n; ++i) {
        read_powersoftau_g1(in, alpha_tau_powers_g1[i]);
    }

    std::vector<G1> beta_tau_powers_g1(n);
    for (size_t i = 0; i < n; ++i) {
        read_powersoftau_g1(in, beta_tau_powers_g1[i]);
    }

    G2 beta_g2;
    read_powersoftau_g2(in, beta_g2);

    srs_powersoftau<ppT> pot(
        std::move(tau_powers_g1),
        std::move(tau_powers_g2),
        std::move(alpha_tau_powers_g1),
        std::move(beta_tau_powers_g1),
        beta_g2);
    check_well_formed(pot, "powersoftau (load)");
    return pot;
}

void powersoftau_write(std::ostream &out, const srs_powersoftau<ppT> &pot)
{
    check_well_formed(pot, "powersoftau (write)");

    // Fake the hash
    uint8_t hash[64];
    memset(hash, 0, sizeof(hash));
    out.write((char *)(&hash[0]), sizeof(hash));

    const size_t n = pot.tau_powers_g2.size();
    const size_t num_powers_of_tau = 2 * n - 1;
    for (size_t i = 0; i < num_powers_of_tau; ++i) {
        write_powersoftau_g1(out, pot.tau_powers_g1[i]);
    }
    for (size_t i = 0; i < n; ++i) {
        write_powersoftau_g2(out, pot.tau_powers_g2[i]);
    }
    for (size_t i = 0; i < n; ++i) {
        write_powersoftau_g1(out, pot.alpha_tau_powers_g1[i]);
    }
    for (size_t i = 0; i < n; ++i) {
        write_powersoftau_g1(out, pot.beta_tau_powers_g1[i]);
    }
    write_powersoftau_g2(out, pot.beta_g2);
}

} // namespace libzeth
