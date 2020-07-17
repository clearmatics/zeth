// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_MPC_GROTH16_POWERSOFTAU_UTILS_TCC__
#define __ZETH_MPC_GROTH16_POWERSOFTAU_UTILS_TCC__

#include "libzeth/core/utils.hpp"
#include "libzeth/mpc/groth16/powersoftau_utils.hpp"

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/fields/fp.hpp>
#include <thread>

namespace libzeth
{

namespace
{

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
        el.coeffs[0].mont_repr.data, // remainder
        0,
        packed.data,
        n * 2,
        modulus.data,
        n);

    for (size_t i = 0; i < n; ++i) {
        el.coeffs[1].mont_repr.data[i] = c1.data[i];
    }

    to_montgomery_repr(el.coeffs[0]);
    to_montgomery_repr(el.coeffs[1]);

    return in;
}

template<mp_size_t n, const libff::bigint<n> &modulus>
void write_powersoftau_fp2(
    std::ostream &out, const libff::Fp2_model<n, modulus> &fp2)
{
    // Fq2 data is packed into a single 512 bit integer as:
    //
    //   c1 * modulus + c0
    libff::Fp_model<n, modulus> c0 = from_montgomery_repr(fp2.coeffs[0]);
    libff::Fp_model<n, modulus> c1 = from_montgomery_repr(fp2.coeffs[1]);

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

// Use the technique described in Section 3 of "A multi-party protocol
// for constructing the public parameters of the Pinocchio zk-SNARK"
// (https://eprint.iacr.org/2017/602.pdf)
// to efficiently evaluate Lagrange polynomials ${L_i(x)}_i$ for the
// $d=2^n$-roots of unity, given powers ${x^i}_i$ for $i=0..d-1$.
template<typename Fr, typename Gr>
static void compute_lagrange_from_powers(
    std::vector<Gr> &powers, const Fr &omega_inv)
{
    libfqfft::_basic_radix2_FFT<Fr, Gr>(powers, omega_inv);
    const Fr n_inv = Fr(powers.size()).inverse();
    for (auto &a : powers) {
        a = n_inv * a;
    }
}

// Given two sequences `as` and `bs` of group elements, compute
//   a_accum = as[0] * r_0 + ... + as[n] * r_n
//   b_accum = bs[0] * r_0 + ... + bs[n] * r_n
// for random scalars r_0 ... r_n.
template<typename ppT, typename G>
void random_linear_combination(
    const std::vector<G> &as, const std::vector<G> &bs, G &a_accum, G &b_accum)
{
    if (as.size() != bs.size()) {
        throw std::invalid_argument(
            "vector size mismatch (random_linear_comb)");
    }

    a_accum = G::zero();
    b_accum = G::zero();

    // Split across threads, each one accumulating into its own thread-local
    // variable, and then (atomically) adding that to the global a1_accum and
    // b1_accum values. These final sums are then used in the final pairing
    // check.
#ifdef MULTICORE
#pragma omp parallel shared(a_accum, b_accum)
#endif
    {
        G a_thread_accum = G::zero();
        G b_thread_accum = G::zero();

        const size_t scalar_bits = libff::Fr<ppT>::num_bits;
        const size_t window_size = libff::wnaf_opt_window_size<G>(scalar_bits);
        std::vector<long> wnaf;

#ifdef MULTICORE
#pragma omp for
#endif
        for (size_t i = 0; i < as.size(); ++i) {
            const libff::Fr<ppT> r = libff::Fr<ppT>::random_element();
            update_wnaf(wnaf, window_size, r.as_bigint());
            G r_ai = fixed_window_wnaf_exp(window_size, as[i], wnaf);
            G r_bi = fixed_window_wnaf_exp(window_size, bs[i], wnaf);

            a_thread_accum = a_thread_accum + r_ai;
            b_thread_accum = b_thread_accum + r_bi;
        }

#ifdef MULTICORE
#pragma omp critical
#endif
        {
            a_accum = a_accum + a_thread_accum;
            b_accum = b_accum + b_thread_accum;
        }
    }
}

// Similar to random_linear_combination, but compute:
//   a_accum = as[0] * r_0 + ... + as[n-1] * r_{n-1}
//   b_accum = bs[1] * r_0 + ... + bs[n  ] * r_{n-1}
// for checking consistent ratio of consecutive entries.
template<typename ppT, typename G>
void random_linear_combination_consecutive(
    const std::vector<G> &as, G &a_accum, G &b_accum)
{
    a_accum = G::zero();
    b_accum = G::zero();

    const size_t num_entries = as.size() - 1;

#ifdef MULTICORE
#pragma omp parallel shared(a_accum, b_accum)
#endif
    {
        G a_thread_accum = G::zero();
        G b_thread_accum = G::zero();

        const size_t scalar_bits = libff::Fr<ppT>::num_bits;
        const size_t window_size = libff::wnaf_opt_window_size<G>(scalar_bits);
        std::vector<long> wnaf;

#ifdef MULTICORE
#pragma omp for
#endif
        for (size_t i = 0; i < num_entries; ++i) {
            const libff::Fr<ppT> r = libff::Fr<ppT>::random_element();
            update_wnaf(wnaf, window_size, r.as_bigint());
            G r_ai = fixed_window_wnaf_exp(window_size, as[i], wnaf);
            G r_bi = fixed_window_wnaf_exp(window_size, as[i + 1], wnaf);

            a_thread_accum = a_thread_accum + r_ai;
            b_thread_accum = b_thread_accum + r_bi;
        }

#ifdef MULTICORE
#pragma omp critical
#endif
        {
            a_accum = a_accum + a_thread_accum;
            b_accum = b_accum + b_thread_accum;
        }
    }
}

} // namespace

// -----------------------------------------------------------------------------
// powersoftau
// -----------------------------------------------------------------------------

template<typename ppT>
srs_powersoftau<ppT>::srs_powersoftau(
    libff::G1_vector<ppT> &&tau_powers_g1,
    libff::G2_vector<ppT> &&tau_powers_g2,
    libff::G1_vector<ppT> &&alpha_tau_powers_g1,
    libff::G1_vector<ppT> &&beta_tau_powers_g1,
    const libff::G2<ppT> &beta_g2)
    : tau_powers_g1(std::move(tau_powers_g1))
    , tau_powers_g2(std::move(tau_powers_g2))
    , alpha_tau_powers_g1(std::move(alpha_tau_powers_g1))
    , beta_tau_powers_g1(std::move(beta_tau_powers_g1))
    , beta_g2(beta_g2)
{
}

template<typename ppT> bool srs_powersoftau<ppT>::is_well_formed() const
{
    return libzeth::container_is_well_formed(tau_powers_g1) &&
           libzeth::container_is_well_formed(tau_powers_g2) &&
           libzeth::container_is_well_formed(alpha_tau_powers_g1) &&
           libzeth::container_is_well_formed(beta_tau_powers_g1) &&
           beta_g2.is_well_formed();
}

// -----------------------------------------------------------------------------
// powersoftau_lagrange_evaluations
// -----------------------------------------------------------------------------

template<typename ppT>
srs_lagrange_evaluations<ppT>::srs_lagrange_evaluations(
    size_t degree,
    std::vector<libff::G1<ppT>> &&lagrange_g1,
    std::vector<libff::G2<ppT>> &&lagrange_g2,
    std::vector<libff::G1<ppT>> &&alpha_lagrange_g1,
    std::vector<libff::G1<ppT>> &&beta_lagrange_g1)
    : degree(degree)
    , lagrange_g1(std::move(lagrange_g1))
    , lagrange_g2(std::move(lagrange_g2))
    , alpha_lagrange_g1(std::move(alpha_lagrange_g1))
    , beta_lagrange_g1(std::move(beta_lagrange_g1))
{
}

template<typename ppT>
bool srs_lagrange_evaluations<ppT>::is_well_formed() const
{
    return container_is_well_formed(lagrange_g1) &&
           container_is_well_formed(lagrange_g2) &&
           container_is_well_formed(alpha_lagrange_g1) &&
           container_is_well_formed(beta_lagrange_g1);
}

template<typename ppT>
void srs_lagrange_evaluations<ppT>::write(std::ostream &out) const
{
    check_well_formed(*this, "powersoftau (write)");

    out.write((const char *)&degree, sizeof(degree));
    for (const libff::G1<ppT> &l_g1 : lagrange_g1) {
        out << l_g1;
    }
    for (const libff::G2<ppT> &l_g2 : lagrange_g2) {
        out << l_g2;
    }
    for (const libff::G1<ppT> &alpha_l_g1 : alpha_lagrange_g1) {
        out << alpha_l_g1;
    }
    for (const libff::G1<ppT> &beta_l_g1 : beta_lagrange_g1) {
        out << beta_l_g1;
    }
}

template<typename ppT>
srs_lagrange_evaluations<ppT> srs_lagrange_evaluations<ppT>::read(
    std::istream &in)
{
    size_t degree;
    in.read((char *)&degree, sizeof(degree));

    std::vector<libff::G1<ppT>> lagrange_g1(degree);
    std::vector<libff::G2<ppT>> lagrange_g2(degree);
    std::vector<libff::G1<ppT>> alpha_lagrange_g1(degree);
    std::vector<libff::G1<ppT>> beta_lagrange_g1(degree);

    for (libff::G1<ppT> &l_g1 : lagrange_g1) {
        in >> l_g1;
    }
    for (libff::G2<ppT> &l_g2 : lagrange_g2) {
        in >> l_g2;
    }
    for (libff::G1<ppT> &alpha_l_g1 : alpha_lagrange_g1) {
        in >> alpha_l_g1;
    }
    for (libff::G1<ppT> &beta_l_g1 : beta_lagrange_g1) {
        in >> beta_l_g1;
    }

    srs_lagrange_evaluations<ppT> lagrange(
        degree,
        std::move(lagrange_g1),
        std::move(lagrange_g2),
        std::move(alpha_lagrange_g1),
        std::move(beta_lagrange_g1));
    check_well_formed(lagrange, "lagrange (read)");
    return lagrange;
}

template<typename ppT>
srs_powersoftau<ppT> dummy_powersoftau_from_secrets(
    const libff::Fr<ppT> &tau,
    const libff::Fr<ppT> &alpha,
    const libff::Fr<ppT> &beta,
    size_t n)
{
    libff::enter_block("dummy_phase1_from_secrets");

    // Compute powers. Note zero-th power is included (alpha_g1 etc
    // are provided in this way), so to support order N polynomials,
    // N+1 entries are required.
    const size_t num_tau_powers_g1 = 2 * n - 2 + 1;
    libff::G1_vector<ppT> tau_powers_g1;
    libff::G2_vector<ppT> tau_powers_g2;
    libff::G1_vector<ppT> alpha_tau_powers_g1;
    libff::G1_vector<ppT> beta_tau_powers_g1;

    libff::enter_block("tau powers");
    std::vector<libff::Fr<ppT>> tau_powers(num_tau_powers_g1);
    tau_powers[0] = libff::Fr<ppT>::one();
    for (size_t i = 1; i < num_tau_powers_g1; ++i) {
        tau_powers[i] = tau * tau_powers[i - 1];
    }
    libff::leave_block("tau powers");

    libff::enter_block("window tables");
    const size_t window_size = libff::get_exp_window_size<libff::G1<ppT>>(n);
    const size_t window_size_tau_g1 =
        libff::get_exp_window_size<libff::G1<ppT>>(2 * n - 1);

    libff::window_table<libff::G1<ppT>> tau_g1_table;
    libff::window_table<libff::G2<ppT>> tau_g2_table;
    libff::window_table<libff::G1<ppT>> alpha_tau_g1_table;
    libff::window_table<libff::G1<ppT>> beta_tau_g1_table;
    {
        std::thread tau_g1_table_thread([&tau_g1_table, window_size_tau_g1]() {
            tau_g1_table = libff::get_window_table(
                libff::G1<ppT>::size_in_bits(),
                window_size_tau_g1,
                libff::G1<ppT>::one());
        });

        std::thread tau_g2_table_thread([&tau_g2_table, window_size]() {
            tau_g2_table = libff::get_window_table(
                libff::G2<ppT>::size_in_bits(),
                window_size,
                libff::G2<ppT>::one());
        });

        std::thread alpha_tau_g1_table_thread(
            [&alpha_tau_g1_table, window_size, alpha]() {
                alpha_tau_g1_table = libff::get_window_table(
                    libff::G1<ppT>::size_in_bits(),
                    window_size,
                    alpha * libff::G1<ppT>::one());
            });

        std::thread beta_tau_g1_table_thread(
            [&beta_tau_g1_table, window_size, beta]() {
                beta_tau_g1_table = libff::get_window_table(
                    libff::G1<ppT>::size_in_bits(),
                    window_size,
                    beta * libff::G1<ppT>::one());
            });

        tau_g1_table_thread.join();
        tau_g2_table_thread.join();
        alpha_tau_g1_table_thread.join();
        beta_tau_g1_table_thread.join();
    }
    libff::leave_block("window tables");

    libff::enter_block("tau_g1 powers");
    tau_powers_g1 = libff::batch_exp(
        libff::G1<ppT>::size_in_bits(),
        window_size_tau_g1,
        tau_g1_table,
        tau_powers);
    libff::leave_block("tau_g1 powers");

    libff::enter_block("tau_g2 powers");
    tau_powers_g2 = libff::batch_exp(
        libff::G2<ppT>::size_in_bits(),
        window_size,
        tau_g2_table,
        tau_powers,
        n);
    libff::leave_block("tau_g2 powers");

    libff::enter_block("alpha_tau_g1 powers");
    alpha_tau_powers_g1 = libff::batch_exp(
        libff::G1<ppT>::size_in_bits(),
        window_size,
        alpha_tau_g1_table,
        tau_powers,
        n);
    libff::leave_block("alpha_tau_g1 powers");

    libff::enter_block("beta_tau_g1 powers");
    beta_tau_powers_g1 = libff::batch_exp(
        libff::G1<ppT>::size_in_bits(),
        window_size,
        beta_tau_g1_table,
        tau_powers,
        n);
    libff::leave_block("beta_tau_g1 powers");

    libff::leave_block("dummy_phase1_from_secrets");
    return srs_powersoftau<ppT>(
        std::move(tau_powers_g1),
        std::move(tau_powers_g2),
        std::move(alpha_tau_powers_g1),
        std::move(beta_tau_powers_g1),
        beta * libff::G2<ppT>::one());
}

template<typename ppT> srs_powersoftau<ppT> dummy_powersoftau(size_t n)
{
    libff::Fr<ppT> tau = libff::Fr<ppT>::random_element();
    libff::Fr<ppT> alpha = libff::Fr<ppT>::random_element();
    libff::Fr<ppT> beta = libff::Fr<ppT>::random_element();

    return dummy_powersoftau_from_secrets<ppT>(tau, alpha, beta, n);
}

template<typename ppT>
void read_powersoftau_fr(std::istream &in, libff::Fr<ppT> &out)
{
    read_powersoftau_fp(in, out);
}

template<typename ppT>
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

/// Structure of G2 varies between pairings, so difficult to implement
/// generically. A specialized version for alt_bn128_pp is provided for
/// compatibility with https://github.com/clearmatics/powersoftau.
template<>
void read_powersoftau_g2<libff::alt_bn128_pp>(
    std::istream &, libff::alt_bn128_G2 &);

template<typename ppT>
void read_powersoftau_g2(std::istream &in, libff::G2<ppT> &out)
{
    in >> out;
}

template<typename ppT>
void write_powersoftau_fr(std::ostream &out, const libff::Fr<ppT> &fr)
{
    write_powersoftau_fp(out, fr);
}

template<typename ppT>
void write_powersoftau_g1(std::ostream &out, const libff::G1<ppT> &g1)
{
    if (g1.is_zero()) {
        const uint8_t zero = 0;
        out.write((const char *)&zero, 1);
        return;
    }

    libff::G1<ppT> copy(g1);
    copy.to_affine_coordinates();

    const uint8_t marker = 0x04;
    out.write((const char *)&marker, 1);
    write_powersoftau_fp(out, copy.X);
    write_powersoftau_fp(out, copy.Y);
}

/// Structure of G2 varies between pairings, so difficult to implement
/// generically. A specialized version for alt_bn128_pp is provided for
/// compatibility with https://github.com/clearmatics/powersoftau.
template<>
void write_powersoftau_g2<libff::alt_bn128_pp>(
    std::ostream &, const libff::alt_bn128_G2 &);

template<typename ppT>
void write_powersoftau_g2(std::ostream &out, const libff::G2<ppT> &g2)
{
    out << g2;
}

template<typename ppT>
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
        read_powersoftau_g1<ppT>(in, tau_powers_g1[i]);
    }
    if (tau_powers_g1[0] != G1::one()) {
        throw std::invalid_argument("invalid powersoftau file?");
    }

    std::vector<G2> tau_powers_g2(n);
    for (size_t i = 0; i < n; ++i) {
        read_powersoftau_g2<ppT>(in, tau_powers_g2[i]);
    }
    if (tau_powers_g2[0] != G2::one()) {
        throw std::invalid_argument("invalid powersoftau file?");
    }

    std::vector<G1> alpha_tau_powers_g1(n);
    for (size_t i = 0; i < n; ++i) {
        read_powersoftau_g1<ppT>(in, alpha_tau_powers_g1[i]);
    }

    std::vector<G1> beta_tau_powers_g1(n);
    for (size_t i = 0; i < n; ++i) {
        read_powersoftau_g1<ppT>(in, beta_tau_powers_g1[i]);
    }

    G2 beta_g2;
    read_powersoftau_g2<ppT>(in, beta_g2);

    srs_powersoftau<ppT> pot(
        std::move(tau_powers_g1),
        std::move(tau_powers_g2),
        std::move(alpha_tau_powers_g1),
        std::move(beta_tau_powers_g1),
        beta_g2);
    check_well_formed(pot, "powersoftau (load)");
    return pot;
}

template<typename ppT>
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
        write_powersoftau_g1<ppT>(out, pot.tau_powers_g1[i]);
    }
    for (size_t i = 0; i < n; ++i) {
        write_powersoftau_g2<ppT>(out, pot.tau_powers_g2[i]);
    }
    for (size_t i = 0; i < n; ++i) {
        write_powersoftau_g1<ppT>(out, pot.alpha_tau_powers_g1[i]);
    }
    for (size_t i = 0; i < n; ++i) {
        write_powersoftau_g1<ppT>(out, pot.beta_tau_powers_g1[i]);
    }
    write_powersoftau_g2<ppT>(out, pot.beta_g2);
}

template<typename ppT>
bool same_ratio(
    const libff::G1<ppT> &a1,
    const libff::G1<ppT> &b1,
    const libff::G2<ppT> &a2,
    const libff::G2<ppT> &b2)
{
    const libff::G1_precomp<ppT> &a1_precomp = ppT::precompute_G1(a1);
    const libff::G1_precomp<ppT> &b1_precomp = ppT::precompute_G1(b1);
    const libff::G2_precomp<ppT> &a2_precomp = ppT::precompute_G2(a2);
    const libff::G2_precomp<ppT> &b2_precomp = ppT::precompute_G2(b2);

    const libff::Fqk<ppT> a1b2 = ppT::miller_loop(a1_precomp, b2_precomp);
    const libff::Fqk<ppT> b1a2 = ppT::miller_loop(b1_precomp, a2_precomp);

    const libff::GT<ppT> a1b2_gt = ppT::final_exponentiation(a1b2);
    const libff::GT<ppT> b1a2_gt = ppT::final_exponentiation(b1a2);

    // Decide whether ratio a1:b1 in G1 equals a2:b2 in G2 by checking:
    //   e(a1, b2) =?= e(b1, a2)
    return a1b2_gt == b1a2_gt;
}

template<typename ppT>
bool same_ratio_vectors(
    const std::vector<libff::G1<ppT>> &a1s,
    const std::vector<libff::G1<ppT>> &b1s,
    const libff::G2<ppT> &a2,
    const libff::G2<ppT> &b2)
{
    using G1 = libff::G1<ppT>;

    libff::enter_block("call to same_ratio_vectors (G1)");
    if (a1s.size() != b1s.size()) {
        throw std::invalid_argument("vector size mismatch in same_ratio_batch");
    }

    libff::enter_block("accumulating random combination");
    G1 a1_accum;
    G1 b1_accum;
    random_linear_combination<ppT>(a1s, b1s, a1_accum, b1_accum);
    libff::leave_block("accumulating random combination");

    const bool same = same_ratio<ppT>(a1_accum, b1_accum, a2, b2);
    libff::leave_block("call to same_ratio_vectors (G1)");
    return same;
}

template<typename ppT>
bool same_ratio_vectors(
    const libff::G1<ppT> &a1,
    const libff::G1<ppT> &b1,
    const std::vector<libff::G2<ppT>> &a2s,
    const std::vector<libff::G2<ppT>> &b2s)
{
    using G2 = libff::G2<ppT>;

    libff::enter_block("call to same_ratio_vectors (G2)");
    if (a2s.size() != b2s.size()) {
        throw std::invalid_argument("vector size mismatch in same_ratio_batch");
    }

    libff::enter_block("accumulating random combination");
    G2 a2_accum;
    G2 b2_accum;
    random_linear_combination<ppT>(a2s, b2s, a2_accum, b2_accum);
    libff::leave_block("accumulating random combination");

    const bool same = same_ratio<ppT>(a1, b1, a2_accum, b2_accum);
    libff::leave_block("call to same_ratio_vectors (G2)");
    return same;
}

template<typename ppT>
bool same_ratio_consecutive(
    const std::vector<libff::G1<ppT>> &a1s,
    const libff::G2<ppT> &a2,
    const libff::G2<ppT> &b2)
{
    using G1 = libff::G1<ppT>;

    libff::enter_block("call to same_ratio_consecutive (G1)");

    libff::enter_block("accumulating random combination");
    G1 a1_accum;
    G1 b1_accum;
    random_linear_combination_consecutive<ppT>(a1s, a1_accum, b1_accum);
    libff::leave_block("accumulating random combination");

    const bool same = same_ratio<ppT>(a1_accum, b1_accum, a2, b2);
    libff::leave_block("call to same_ratio_consecutive (G1)");
    return same;
}

template<typename ppT>
bool same_ratio_consecutive(
    const libff::G1<ppT> &a1,
    const libff::G1<ppT> &b1,
    const std::vector<libff::G2<ppT>> &a2s)
{
    using G2 = libff::G2<ppT>;

    libff::enter_block("call to same_ratio_consecutive (G2)");

    libff::enter_block("accumulating random combination");
    G2 a2_accum;
    G2 b2_accum;
    random_linear_combination_consecutive<ppT>(a2s, a2_accum, b2_accum);
    libff::leave_block("accumulating random combination");

    const bool same = same_ratio<ppT>(a1, b1, a2_accum, b2_accum);
    libff::leave_block("call to same_ratio_consecutive (G2)");
    return same;
}

template<typename ppT>
bool powersoftau_is_well_formed(const srs_powersoftau<ppT> &pot)
{
    // TODO: Cache precomputed g1, tau_g1, g2, tau_g2
    // TODO: Parallelize

    // Check sizes are valid. tau_powers_g1 should have 2n-1 elements, and
    // other vectors should have n entries.
    const size_t n = (pot.tau_powers_g1.size() + 1) / 2;
    if (n != 1ull << libff::log2(n) || n != pot.tau_powers_g2.size() ||
        n != pot.alpha_tau_powers_g1.size() ||
        n != pot.beta_tau_powers_g1.size()) {
        return false;
    }

    // Make sure that the identity of each group is at index 0
    if (pot.tau_powers_g1[0] != libff::G1<ppT>::one() ||
        pot.tau_powers_g2[0] != libff::G2<ppT>::one()) {
        return false;
    }

    const libff::G1<ppT> g1 = libff::G1<ppT>::one();
    const libff::G2<ppT> g2 = libff::G2<ppT>::one();
    const libff::G1<ppT> tau_g1 = pot.tau_powers_g1[1];
    const libff::G2<ppT> tau_g2 = pot.tau_powers_g2[1];

    // SameRatio((g1, tau_g1), (g2, tau_g2))
    const bool tau_g1_g2_consistent =
        same_ratio<ppT>(g1, pot.tau_powers_g1[1], g2, pot.tau_powers_g2[1]);
    if (!tau_g1_g2_consistent) {
        return false;
    }

    // SameRatio((tau_powers_g1[i-1], tau_powers_g1[i]), (g2, tau_g2))
    // SameRatio((tau_powers_g2[i-1], tau_powers_g2[i]), (g1, tau_g1))
    // SameRatio(
    //     (alpha_tau_powers_g1[i-1], alpha_tau_powers_g1[i]), (g2, tau_g2))
    // SameRatio(
    //     (beta_tau_powers_g1[i-1], beta_tau_powers_g1[i]), (g2, tau_g2))
    if (!same_ratio_consecutive<ppT>(pot.tau_powers_g1, g2, tau_g2) ||
        !same_ratio_consecutive<ppT>(g1, tau_g1, pot.tau_powers_g2) ||
        !same_ratio_consecutive<ppT>(pot.alpha_tau_powers_g1, g2, tau_g2) ||
        !same_ratio_consecutive<ppT>(pot.beta_tau_powers_g1, g2, tau_g2)) {
        return false;
    }

    // SameRatio((g1, beta_tau_powers_g1), (g2, beta_g2))
    if (!same_ratio<ppT>(g1, pot.beta_tau_powers_g1[0], g2, pot.beta_g2)) {
        return false;
    }

    return true;
}

template<typename ppT>
srs_lagrange_evaluations<ppT> powersoftau_compute_lagrange_evaluations(
    const srs_powersoftau<ppT> &pot, const size_t n)
{
    using Fr = libff::Fr<ppT>;
    using G1 = libff::G1<ppT>;
    using G2 = libff::G2<ppT>;

    if (n != 1ull << libff::log2(n)) {
        throw std::invalid_argument("non-pow-2 domain");
    }
    if (pot.tau_powers_g1.size() < n) {
        throw std::invalid_argument("insufficient powers of tau");
    }

    libff::enter_block("r1cs_gg_ppzksnark_compute_lagrange_evaluations");
    libff::print_indent();
    printf("n=%zu\n", n);

    libfqfft::basic_radix2_domain<Fr> domain(n);
    const Fr omega = domain.get_domain_element(1);
    const Fr omega_inv = omega.inverse();

    // Compute [ L_j(t) ]_1 from { [x^i] } i=0..n-1
    libff::enter_block("computing [Lagrange_i(x)]_1");
    std::vector<G1> lagrange_g1(
        pot.tau_powers_g1.begin(), pot.tau_powers_g1.begin() + n);
    if (lagrange_g1[0] != G1::one() || lagrange_g1.size() != n) {
        throw std::invalid_argument("unexpected powersoftau data (g1). Invalid "
                                    "file or degree mismatch");
    }
    compute_lagrange_from_powers(lagrange_g1, omega_inv);
    libff::leave_block("computing [Lagrange_i(x)]_1");

    libff::enter_block("computing [Lagrange_i(x)]_2");
    std::vector<G2> lagrange_g2(
        pot.tau_powers_g2.begin(), pot.tau_powers_g2.begin() + n);
    if (lagrange_g2[0] != G2::one() || lagrange_g2.size() != n) {
        throw std::invalid_argument("unexpected powersoftau data (g2). invalid "
                                    "file or degree mismatch");
    }
    compute_lagrange_from_powers(lagrange_g2, omega_inv);
    libff::leave_block("computing [Lagrange_i(x)]_2");

    libff::enter_block("computing [alpha . Lagrange_i(x)]_1");
    std::vector<G1> alpha_lagrange_g1(
        pot.alpha_tau_powers_g1.begin(), pot.alpha_tau_powers_g1.begin() + n);
    if (alpha_lagrange_g1.size() != n) {
        throw std::invalid_argument("unexpected powersoftau data (alpha). "
                                    "invalid file or degree mismatch");
    }
    compute_lagrange_from_powers(alpha_lagrange_g1, omega_inv);
    libff::leave_block("computing [alpha . Lagrange_i(x)]_1");

    libff::enter_block("computing [beta . Lagrange_i(x)]_1");
    std::vector<G1> beta_lagrange_g1(
        pot.beta_tau_powers_g1.begin(), pot.beta_tau_powers_g1.begin() + n);
    if (beta_lagrange_g1.size() != n) {
        throw std::invalid_argument("unexpected powersoftau data (alpha). "
                                    "invalid file or degree mismatch");
    }
    compute_lagrange_from_powers(beta_lagrange_g1, omega_inv);
    libff::leave_block("computing [beta . Lagrange_i(x)]_1");

    libff::leave_block("r1cs_gg_ppzksnark_compute_lagrange_evaluations");

    return srs_lagrange_evaluations<ppT>(
        n,
        std::move(lagrange_g1),
        std::move(lagrange_g2),
        std::move(alpha_lagrange_g1),
        std::move(beta_lagrange_g1));
}

} // namespace libzeth

#endif // __ZETH_MPC_GROTH16_POWERSOFTAU_UTILS_TCC__
