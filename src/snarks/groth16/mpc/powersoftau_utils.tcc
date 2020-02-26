// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SNARKS_GROTH16_POWERSOFTAU_UTILS_TCC__
#define __ZETH_SNARKS_GROTH16_POWERSOFTAU_UTILS_TCC__

#include "snarks/groth16/mpc/powersoftau_utils.hpp"
#include "util.hpp"

#include <thread>

namespace libzeth
{

namespace
{

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

#endif // __ZETH_SNARKS_GROTH16_POWERSOFTAU_UTILS_TCC__
