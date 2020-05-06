// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/circuits/circuit_types.hpp"
#include "libzeth/core/evaluator_from_lagrange.hpp"
#include "libzeth/mpc/groth16/powersoftau_utils.hpp"

#include <gtest/gtest.h>

using namespace libzeth;
using Fr = FieldT;
using G1 = libff::G1<ppT>;
using G2 = libff::G2<ppT>;

namespace
{

TEST(EvaluationFromLagrangeTest, ComputeLagrangeEvaluation)
{
    const size_t n = 16;

    // dummy phase 1
    Fr tau = Fr::random_element();
    Fr alpha = Fr::random_element();
    Fr beta = Fr::random_element();
    const srs_powersoftau<ppT> pot =
        dummy_powersoftau_from_secrets<ppT>(tau, alpha, beta, n);
    const srs_lagrange_evaluations<ppT> lagrange =
        powersoftau_compute_lagrange_evaluations(pot, n);

    // Compare to the naive evaluations obtained using iFFT in Fr, and
    // evaluating the polynomial.
    libfqfft::basic_radix2_domain<Fr> domain(n);
    evaluator_from_lagrange<ppT, G1> eval_g1(pot.tau_powers_g1, domain);
    evaluator_from_lagrange<ppT, G2> eval_g2(pot.tau_powers_g2, domain);
    evaluator_from_lagrange<ppT, G1> eval_alpha_g1(
        pot.alpha_tau_powers_g1, domain);
    evaluator_from_lagrange<ppT, G1> eval_beta_g1(
        pot.beta_tau_powers_g1, domain);

    for (size_t j = 0; j < n; ++j) {
        printf("j=%zu\n", j);
        std::map<size_t, Fr> l_factors;
        l_factors[j] = Fr::one();

        G1 l_j_g1 = eval_g1.evaluate_from_lagrange_factors(l_factors);
        ASSERT_EQ(l_j_g1, lagrange.lagrange_g1[j])
            << "L_" << std::to_string(j) << " in G1";

        G2 l_j_g2 = eval_g2.evaluate_from_lagrange_factors(l_factors);
        ASSERT_EQ(l_j_g2, lagrange.lagrange_g2[j])
            << "L_" << std::to_string(j) << " in G2";

        G1 alpha_l_j_g1 =
            eval_alpha_g1.evaluate_from_lagrange_factors(l_factors);
        ASSERT_EQ(alpha_l_j_g1, lagrange.alpha_lagrange_g1[j])
            << "alpha L_" << std::to_string(j) << " in G1";

        G1 beta_l_j_g1 = eval_beta_g1.evaluate_from_lagrange_factors(l_factors);
        ASSERT_EQ(beta_l_j_g1, lagrange.beta_lagrange_g1[j])
            << "beta L_" << std::to_string(j) << " in G1";
    }
}

} // namespace

int main(int argc, char **argv)
{
    ppT::init_public_params();
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
