#ifndef __ZETH_CRS_TCC__
#define __ZETH_CRS_TCC__

#include "crs.hpp"
#include "multi_exp.hpp"
#include "evaluation_from_lagrange.hpp"
#include <libff/algebra/scalar_multiplication/multiexp.hpp>

using namespace libsnark;

using ppT = libff::default_ec_pp;
using FieldT = libff::Fr<ppT>;
using Fr = libff::Fr<ppT>;
using G1 = libff::G1<ppT>;
using G2 = libff::G2<ppT>;

///
template<typename ppT>
r1cs_gg_ppzksnark_crs1<ppT>::r1cs_gg_ppzksnark_crs1(
        libff::G1_vector<ppT> &&tau_powers_g1,
        libff::G2_vector<ppT> &&tau_powers_g2,
        libff::G1_vector<ppT> &&alpha_tau_powers_g1,
        libff::G1_vector<ppT> &&beta_tau_powers_g1,
        const libff::G2<ppT> &beta_g2,
        const libff::G1<ppT> &delta_g1,
        const libff::G2<ppT> &delta_g2)
        : tau_powers_g1(std::move(tau_powers_g1))
        , tau_powers_g2(std::move(tau_powers_g2))
        , alpha_tau_powers_g1(std::move(alpha_tau_powers_g1))
        , beta_tau_powers_g1(std::move(beta_tau_powers_g1))
        , beta_g2(beta_g2)
        , delta_g1(delta_g1)
        , delta_g2(delta_g2)
{
}


///
template<typename ppT>
r1cs_gg_ppzksnark_crs2<ppT>::r1cs_gg_ppzksnark_crs2(
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


/// SameRatio( (a1, b1), (a2, b2) )
template <typename ppT>
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

    return a1b2_gt == b1a2_gt;
}


///
template <typename ppT>
bool r1cs_gg_ppzksnark_crs1_validate(
    const r1cs_gg_ppzksnark_crs1<ppT> &crs1,
    const size_t n)
{
    // TODO: Cache precomputed g1, tau_g1, g2, tau_g2
    // TODO: Parallelize

    // One at index 0

    if (crs1.tau_powers_g1[0] != G1::one() ||
        crs1.tau_powers_g2[0] != G2::one())
    {
        return false;
    }

    const size_t num_tau_powers_g1 = 2 * n - 1;
    const G1 g1 = G1::one();
    const G2 g2 = G2::one();
    const G1 tau_g1 = crs1.tau_powers_g1[1];
    const G2 tau_g2 = crs1.tau_powers_g2[1];

    // SameRatio( (g1, tau_g1), (g2, tau_g2) )

    const bool tau_g1_g2_consistent = same_ratio<ppT>(
        g1,
        crs1.tau_powers_g1[1],
        g2,
        crs1.tau_powers_g2[1]);
    if (!tau_g1_g2_consistent)
    {
        return false;
    }

    // SameRatio((tau_powers_g1[i-1], tau_powers_g1[i]), (g2, tau_g2))
    // SameRatio((tau_powers_g2[i-1], tau_powers_g2[i]), (g1, tau_g1))
    // SameRatio(
    //     (alpha_tau_powers_g1[i-1], alpha_tau_powers_g1[i]), (g2, tau_g2))
    // SameRatio(
    //     (beta_tau_powers_g1[i-1], beta_tau_powers_g1[i]), (g2, tau_g2))

    for (size_t i = 1 ; i < n ; ++i)
    {
        if (!same_ratio<ppT>(
                crs1.tau_powers_g1[i-1], crs1.tau_powers_g1[i], g2, tau_g2) ||
            !same_ratio<ppT>(
                g1, tau_g1, crs1.tau_powers_g2[i-1], crs1.tau_powers_g2[i]) ||
            !same_ratio<ppT>(
                crs1.alpha_tau_powers_g1[i-1], crs1.alpha_tau_powers_g1[i], g2, tau_g2) ||
            !same_ratio<ppT>(
                crs1.beta_tau_powers_g1[i-1], crs1.beta_tau_powers_g1[i], g2, tau_g2))
        {
            return false;
        }
    }

    // SameRatio((tau_powers_g1[i-1], tau_powers_g1[i]), (g2, tau_g2))
    // for remaining powers

    for (size_t i = n ; i < num_tau_powers_g1 ; ++i)
    {
        if (!same_ratio<ppT>(
                crs1.tau_powers_g1[i-1], crs1.tau_powers_g1[i], g2, tau_g2))
        {
            return false;
        }
    }

    // SameRatio((g1, beta_tau_powers_g1), (g2, beta_g2))
    // SameRatio((g1, delta_g1), (g2, delta_g2))

    if (!same_ratio<ppT>(g1, crs1.beta_tau_powers_g1[0], g2, crs1.beta_g2) ||
        !same_ratio<ppT>(g1, crs1.delta_g1, g2, crs1.delta_g2))
    {
        return false;
    }

    return true;
}


/// Given a circuit and a crs1, perform the correct linear
/// combinations of elements in crs1 to get the extra from the 2nd
/// layer of the CRS MPC.
r1cs_gg_ppzksnark_crs2<ppT>
r1cs_gg_ppzksnark_generator_phase2(
    const r1cs_gg_ppzksnark_crs1<ppT> &crs1,
    const qap_instance<Fr> &qap)
{
    libfqfft::evaluation_domain<FieldT> &domain = *qap.domain;

    // m = number of constraints in qap / degree of t().
    const size_t m = qap.degree();
    const size_t num_variables = qap.num_variables();

    printf("m: %zu\n", m);
    printf("qap.num_inputs: %zu\n", qap.num_inputs());
    printf("num_variables: %zu\n", num_variables);
    printf("ABC_degree: %zu\n", qap.degree());

    // L's, and therefore A, B, C will have order (m-1).  T has order m.
    // H.t() has order 2m-2, => H(.) has order:
    //
    //   2m-2 - m = m-2
    //
    // Therefore { t(x) . x^i } has 0 .. m-2 (m-1 of them), requiring
    // requires powers of tau 0 ..  2.m-2 (2m-1 of them).  We should
    // have at least this many, by definition.

    assert(crs1.tau_powers_g1.size() >= 2*m - 1);

    // m+1 corefficients of t

    std::vector<Fr> t_coefficients(m + 1, Fr::zero());
    qap.domain->add_poly_Z(Fr::one(), t_coefficients);

    // Compute [ t(x) . x^i ]_1 for i = 0 .. m-2

    libff::G1_vector<ppT> t_x_pow_i(m-1);
    for (size_t i = 0 ; i < m - 1 ; ++i)
    {
        // Use { [x^i] , ... , [x^(i+order_L+1)] } with coefficients
        // of t to compute t(x).x^i.
        t_x_pow_i[i] = multi_exp<ppT, G1>(
            crs1.tau_powers_g1.begin() + i,
            crs1.tau_powers_g1.begin() + i + m + 1,
            t_coefficients.begin(),
            t_coefficients.end());
    }

    // Compute [ beta.A_i(x) + alpha.B_i(x) + C_i(x) ]_1
    //
    // For each i, get the Lagrange factors of A_i, B_i, C_i.  For
    // each j, if A, B or C has a non-zero factor, grab the Lagrange
    // coefficients, evaluate at [t]_1, multiply by the factor and
    // accumulate.

    libff::G1_vector<ppT> A_i_g1(num_variables + 1);
    libff::G1_vector<ppT> B_i_g1(num_variables + 1);
    libff::G2_vector<ppT> B_i_g2(num_variables + 1);
    libff::G1_vector<ppT> ABC_i_g1(num_variables + 1);

    evaluation_from_lagrange<ppT, G1> tau_eval_g1(crs1.tau_powers_g1, domain);
    evaluation_from_lagrange<ppT, G2> tau_eval_g2(crs1.tau_powers_g2, domain);
    evaluation_from_lagrange<ppT, G1> alpha_tau_eval(crs1.alpha_tau_powers_g1, domain);
    evaluation_from_lagrange<ppT, G1> beta_tau_eval(crs1.beta_tau_powers_g1, domain);

    for (size_t i = 0 ; i < num_variables + 1 ; ++i)
    {
        // Compute [beta.A_i(x)], [alpha.B_i(x)] . [C_i(x)]

        const std::map<size_t, Fr> &A_i_in_lagrange = qap.A_in_Lagrange_basis[i];
        const std::map<size_t, Fr> &B_i_in_lagrange = qap.A_in_Lagrange_basis[i];
        const std::map<size_t, Fr> &C_i_in_lagrange = qap.A_in_Lagrange_basis[i];

        A_i_g1[i] = tau_eval_g1.evaluate_from_langrange_factors(A_i_in_lagrange);
        B_i_g1[i] = tau_eval_g1.evaluate_from_langrange_factors(B_i_in_lagrange);
        B_i_g2[i] = tau_eval_g2.evaluate_from_langrange_factors(B_i_in_lagrange);

        G1 beta_A_at_t = beta_tau_eval.evaluate_from_langrange_factors(
            A_i_in_lagrange);
        G1 alpha_B_at_t = alpha_tau_eval.evaluate_from_langrange_factors(
            B_i_in_lagrange);
        G1 C_at_t = tau_eval_g1.evaluate_from_langrange_factors(
            C_i_in_lagrange);

        ABC_i_g1[i] = beta_A_at_t + alpha_B_at_t + C_at_t;
    }

    // TODO: Sparse B

    return r1cs_gg_ppzksnark_crs2<ppT>(
        std::move(t_x_pow_i),
        std::move(A_i_g1),
        std::move(B_i_g1),
        std::move(B_i_g2),
        std::move(ABC_i_g1));
}


/// Given the output from the first two layers of the MPC, perform the
/// 3rd layer computation using just local randomness.  This is not a
/// substitute for the full MPC with an auditable log of contributions,
/// but is useful for testing.
r1cs_gg_ppzksnark_keypair<ppT>
r1cs_gg_ppzksnark_generator_dummy_phase3(
    r1cs_gg_ppzksnark_crs1<ppT> &&crs1,
    r1cs_gg_ppzksnark_crs2<ppT> &&crs2,
    r1cs_constraint_system<libff::Fr<ppT>> &&cs,
    const qap_instance<libff::Fr<ppT>> &qap)
{
    // TODO:

    (void)crs1;
    (void)crs2;
    return r1cs_gg_ppzksnark_keypair<ppT>();
}

#endif // __ZETH_CRS_TCC__
