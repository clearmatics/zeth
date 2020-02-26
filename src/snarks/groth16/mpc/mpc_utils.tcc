// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SNARKS_GROTH16_MPC_UTILS_TCC__
#define __ZETH_SNARKS_GROTH16_MPC_UTILS_TCC__

#include "evaluator_from_lagrange.hpp"
#include "mpc_utils.hpp"
#include "multi_exp.hpp"
#include "phase2.hpp"
#include "util.hpp"

#include <algorithm>
#include <exception>
#include <libfqfft/evaluation_domain/domains/basic_radix2_domain_aux.tcc>

namespace libzeth
{

template<typename ppT>
srs_mpc_layer_L1<ppT>::srs_mpc_layer_L1(
    libff::G1_vector<ppT> &&T_tau_powers_g1,
    libff::G1_vector<ppT> &&A_g1,
    libff::G1_vector<ppT> &&B_g1,
    libff::G2_vector<ppT> &&B_g2,
    libff::G1_vector<ppT> &&ABC_g1)
    : T_tau_powers_g1(std::move(T_tau_powers_g1))
    , A_g1(std::move(A_g1))
    , B_g1(std::move(B_g1))
    , B_g2(std::move(B_g2))
    , ABC_g1(std::move(ABC_g1))
{
}

template<typename ppT> size_t srs_mpc_layer_L1<ppT>::degree() const
{
    return T_tau_powers_g1.size() + 1;
}

template<typename ppT> bool srs_mpc_layer_L1<ppT>::is_well_formed() const
{
    return libzeth::container_is_well_formed(T_tau_powers_g1) &&
           libzeth::container_is_well_formed(A_g1) &&
           libzeth::container_is_well_formed(B_g1) &&
           libzeth::container_is_well_formed(B_g2) &&
           libzeth::container_is_well_formed(ABC_g1);
}

template<typename ppT>
void srs_mpc_layer_L1<ppT>::write(std::ostream &out) const
{
    using G1 = libff::G1<ppT>;
    using G2 = libff::G2<ppT>;
    check_well_formed(*this, "mpc_layer1 (write)");

    // Write the sizes first, then stream out the values.
    const size_t num_T_tau_powers = T_tau_powers_g1.size();
    const size_t num_polynomials = A_g1.size();
    out.write((const char *)&num_T_tau_powers, sizeof(num_T_tau_powers));
    out.write((const char *)&num_polynomials, sizeof(num_polynomials));

    for (const G1 &v : T_tau_powers_g1) {
        out << v;
    }

    for (const G1 &v : A_g1) {
        out << v;
    }

    for (const G1 &v : B_g1) {
        out << v;
    }

    for (const G2 &v : B_g2) {
        out << v;
    }

    for (const G1 &v : ABC_g1) {
        out << v;
    }
}

template<typename ppT>
srs_mpc_layer_L1<ppT> srs_mpc_layer_L1<ppT>::read(std::istream &in)
{
    using G1 = libff::G1<ppT>;
    using G2 = libff::G2<ppT>;

    size_t num_T_tau_powers;
    size_t num_polynomials;

    in.read((char *)&num_T_tau_powers, sizeof(num_T_tau_powers));
    in.read((char *)&num_polynomials, sizeof(num_polynomials));

    libff::G1_vector<ppT> T_tau_powers_g1(num_T_tau_powers);
    libff::G1_vector<ppT> A_g1(num_polynomials);
    libff::G1_vector<ppT> B_g1(num_polynomials);
    libff::G2_vector<ppT> B_g2(num_polynomials);
    libff::G1_vector<ppT> ABC_g1(num_polynomials);

    for (G1 &v : T_tau_powers_g1) {
        in >> v;
    }

    for (G1 &v : A_g1) {
        in >> v;
    }

    for (G1 &v : B_g1) {
        in >> v;
    }

    for (G2 &v : B_g2) {
        in >> v;
    }

    for (G1 &v : ABC_g1) {
        in >> v;
    }

    srs_mpc_layer_L1<ppT> l1(
        std::move(T_tau_powers_g1),
        std::move(A_g1),
        std::move(B_g1),
        std::move(B_g2),
        std::move(ABC_g1));
    check_well_formed(l1, "mpc_layer1 (read)");
    return l1;
}

template<typename ppT>
srs_mpc_layer_L1<ppT> mpc_compute_linearcombination(
    const srs_powersoftau<ppT> &pot,
    const srs_lagrange_evaluations<ppT> &lagrange,
    const libsnark::qap_instance<libff::Fr<ppT>> &qap)
{
    using Fr = libff::Fr<ppT>;
    using G1 = libff::G1<ppT>;
    using G2 = libff::G2<ppT>;
    libff::enter_block("Call to mpc_compute_linearcombination");

    // n = number of constraints in r1cs, or equivalently, n = deg(t(x))
    // t(x) being the target polynomial of the QAP
    // Note: In the code-base the target polynomial is also denoted Z
    // as refered to as "the vanishing polynomial", and t is also used
    // to represent the query point (aka "tau").
    const size_t n = qap.degree();
    const size_t num_variables = qap.num_variables();

    if (n != 1ull << libff::log2(n)) {
        throw std::invalid_argument("non-pow-2 domain");
    }
    if (n != lagrange.degree) {
        throw std::invalid_argument(
            "domain size differs from Lagrange evaluation");
    }

    libff::print_indent();
    printf("n=%zu\n", n);

    // The QAP polynomials A, B, C are of degree (n-1) as we know they
    // are created by interpolation of an r1cs of n constraints.
    // As a consequence, the polynomial (A.B - C) is of degree 2n-2,
    // while the target polynomial t is of degree n.
    // Thus, we need to have access (in the SRS) to powers up to 2n-2.
    // To represent such polynomials we need {x^i} for in {0, ... n-2}
    // hence we check below that we have at least n-1 elements
    // in the set of powers of tau
    assert(pot.tau_powers_g1.size() >= 2 * n - 1);

    // Domain uses n-roots of unity, so
    //      t(x)       = x^n - 1
    //  =>  t(x) . x^i = x^(n+i) - x^i
    libff::G1_vector<ppT> t_x_pow_i(n - 1, G1::zero());
    libff::enter_block("computing [t(x) . x^i]_1");
    for (size_t i = 0; i < n - 1; ++i) {
        t_x_pow_i[i] = pot.tau_powers_g1[n + i] - pot.tau_powers_g1[i];
    }
    libff::leave_block("computing [t(x) . x^i]_1");

    libff::enter_block("computing A_i, B_i, C_i, ABC_i at x");
    libff::G1_vector<ppT> As_g1(num_variables + 1);
    libff::G1_vector<ppT> Bs_g1(num_variables + 1);
    libff::G2_vector<ppT> Bs_g2(num_variables + 1);
    libff::G1_vector<ppT> Cs_g1(num_variables + 1);
    libff::G1_vector<ppT> ABCs_g1(num_variables + 1);
#ifdef MULTICORE
#pragma omp parallel for
#endif
    for (size_t j = 0; j < num_variables + 1; ++j) {
        G1 ABC_j_at_x = G1::zero();

        {
            G1 A_j_at_x = G1::zero();
            const std::map<size_t, Fr> &A_j_lagrange =
                qap.A_in_Lagrange_basis[j];
            for (const auto &entry : A_j_lagrange) {
                A_j_at_x = A_j_at_x +
                           (entry.second * lagrange.lagrange_g1[entry.first]);
                ABC_j_at_x =
                    ABC_j_at_x +
                    (entry.second * lagrange.beta_lagrange_g1[entry.first]);
            }

            As_g1[j] = A_j_at_x;
        }

        {
            G1 B_j_at_x_g1 = G1::zero();
            G2 B_j_at_x_g2 = G2::zero();

            const std::map<size_t, Fr> &B_j_lagrange =
                qap.B_in_Lagrange_basis[j];
            for (const auto &entry : B_j_lagrange) {
                B_j_at_x_g1 = B_j_at_x_g1 + (entry.second *
                                             lagrange.lagrange_g1[entry.first]);
                B_j_at_x_g2 = B_j_at_x_g2 + (entry.second *
                                             lagrange.lagrange_g2[entry.first]);
                ABC_j_at_x =
                    ABC_j_at_x +
                    (entry.second * lagrange.alpha_lagrange_g1[entry.first]);
            }

            Bs_g1[j] = B_j_at_x_g1;
            Bs_g2[j] = B_j_at_x_g2;
        }

        {
            G1 C_j_at_x = G1::zero();
            const std::map<size_t, Fr> &C_j_lagrange =
                qap.C_in_Lagrange_basis[j];
            for (const auto &entry : C_j_lagrange) {
                C_j_at_x =
                    C_j_at_x + entry.second * lagrange.lagrange_g1[entry.first];
            }

            Cs_g1[j] = C_j_at_x;
            ABC_j_at_x = ABC_j_at_x + C_j_at_x;
        }

        ABCs_g1[j] = ABC_j_at_x;
    }
    libff::leave_block("computing A_i, B_i, C_i, ABC_i at x");

    // TODO: Consider dropping those entries we know will not be used
    // by this circuit and using sparse vectors where it makes sense
    // (as is done for B_i's in r1cs_gg_ppzksnark_proving_key).
    libff::leave_block("Call to mpc_compute_linearcombination");

    return srs_mpc_layer_L1<ppT>(
        std::move(t_x_pow_i),
        std::move(As_g1),
        std::move(Bs_g1),
        std::move(Bs_g2),
        std::move(ABCs_g1));
}

} // namespace libzeth

#endif // __ZETH_SNARKS_GROTH16_MPC_UTILS_TCC__
