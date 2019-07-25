
#include "snarks/groth16/crs.hpp"
#include "test/simple_test.hpp"

#include <gtest/gtest.h>

using ppT = libff::default_ec_pp;
using Fr = libff::Fr<ppT>;
using G1 = libff::G1<ppT>;
using G2 = libff::G2<ppT>;
using namespace libsnark;

namespace
{

// Compute a dummy set of powers-of-tau, for circuits with up to
// polynomials order-bound by `n` .
r1cs_gg_ppzksnark_crs1<ppT> dummy_phase1(size_t n)
{
    Fr tau = Fr::random_element();
    Fr alpha = Fr::random_element();
    Fr beta = Fr::random_element();
    Fr delta = Fr::random_element();

    // Compute powers.  Note zero-th power is included (alpha_g1 etc
    // are provided in this way), so to support order N polynomials,
    // N+1 entries are required.

    const size_t num_tau_powers_g1 = 2 * n - 2 + 1;
    libff::G1_vector<ppT> tau_powers_g1(num_tau_powers_g1);
    libff::G2_vector<ppT> tau_powers_g2(n);
    libff::G1_vector<ppT> alpha_tau_powers_g1(n);
    libff::G1_vector<ppT> beta_tau_powers_g1(n);

    tau_powers_g1[0] = G1::one();
    tau_powers_g2[0] = G2::one();
    alpha_tau_powers_g1[0] = alpha * G1::one();
    beta_tau_powers_g1[0] = beta * G1::one();

    for (size_t i = 1 ; i < n ; ++i)
    {
        tau_powers_g1[i] = tau * tau_powers_g1[i-1];
        tau_powers_g2[i] = tau * tau_powers_g2[i-1];
        alpha_tau_powers_g1[i] = tau * alpha_tau_powers_g1[i-1];
        beta_tau_powers_g1[i] = tau * beta_tau_powers_g1[i-1];
    }

    for (size_t i = n ; i < num_tau_powers_g1 ; ++i)
    {
        tau_powers_g1[i] = tau * tau_powers_g1[i-1];
    }

    return r1cs_gg_ppzksnark_crs1<ppT>(
        std::move(tau_powers_g1),
        std::move(tau_powers_g2),
        std::move(alpha_tau_powers_g1),
        std::move(beta_tau_powers_g1),
        beta * G2::one(),
        delta * G1::one(),
        delta * G2::one());
}


TEST(CRSTests, CRS1Validation)
{
    // Remove stdout noise from libff
    libff::inhibit_profiling_counters = true;

    const size_t n = 16;
    const r1cs_gg_ppzksnark_crs1<ppT> crs1 = dummy_phase1(n);

    ASSERT_TRUE(r1cs_gg_ppzksnark_crs1_validate(crs1, n));

    // tamper with some individual entries

    {
        libff::G1_vector<ppT> tau_powers_g1 = crs1.tau_powers_g1;
        tau_powers_g1[2] = tau_powers_g1[2] + G1::one();
        const r1cs_gg_ppzksnark_crs1<ppT> tamper_tau_g1(
            std::move(tau_powers_g1),
            libff::G2_vector<ppT>(crs1.tau_powers_g2),
            libff::G1_vector<ppT>(crs1.alpha_tau_powers_g1),
            libff::G1_vector<ppT>(crs1.beta_tau_powers_g1),
            crs1.beta_g2,
            crs1.delta_g1,
            crs1.delta_g2);

        ASSERT_FALSE(r1cs_gg_ppzksnark_crs1_validate(tamper_tau_g1, n));
    }

    {
        libff::G2_vector<ppT> tau_powers_g2 = crs1.tau_powers_g2;
        tau_powers_g2[2] = tau_powers_g2[2] + G2::one();
        const r1cs_gg_ppzksnark_crs1<ppT> tamper_tau_g2(
            libff::G1_vector<ppT>(crs1.tau_powers_g1),
            std::move(tau_powers_g2),
            libff::G1_vector<ppT>(crs1.alpha_tau_powers_g1),
            libff::G1_vector<ppT>(crs1.beta_tau_powers_g1),
            crs1.beta_g2,
            crs1.delta_g1,
            crs1.delta_g2);

        ASSERT_FALSE(r1cs_gg_ppzksnark_crs1_validate(tamper_tau_g2, n));
    }

    {
        libff::G1_vector<ppT> alpha_tau_powers_g1 = crs1.alpha_tau_powers_g1;
        alpha_tau_powers_g1[2] = alpha_tau_powers_g1[2] + G1::one();
        const r1cs_gg_ppzksnark_crs1<ppT> tamper_alpha_tau_g1(
            libff::G1_vector<ppT>(crs1.tau_powers_g1),
            libff::G2_vector<ppT>(crs1.tau_powers_g2),
            std::move(alpha_tau_powers_g1),
            libff::G1_vector<ppT>(crs1.beta_tau_powers_g1),
            crs1.beta_g2,
            crs1.delta_g1,
            crs1.delta_g2);

        ASSERT_FALSE(r1cs_gg_ppzksnark_crs1_validate(tamper_alpha_tau_g1, n));
    }

    {
        libff::G1_vector<ppT> beta_tau_powers_g1 = crs1.beta_tau_powers_g1;
        beta_tau_powers_g1[2] = beta_tau_powers_g1[2] + G1::one();
        const r1cs_gg_ppzksnark_crs1<ppT> tamper_beta_tau_g1(
            libff::G1_vector<ppT>(crs1.tau_powers_g1),
            libff::G2_vector<ppT>(crs1.tau_powers_g2),
            libff::G1_vector<ppT>(crs1.alpha_tau_powers_g1),
            std::move(beta_tau_powers_g1),
            crs1.beta_g2,
            crs1.delta_g1,
            crs1.delta_g2);

        ASSERT_FALSE(r1cs_gg_ppzksnark_crs1_validate(tamper_beta_tau_g1, n));
    }

    {
        const r1cs_gg_ppzksnark_crs1<ppT> tamper_beta_g2(
            libff::G1_vector<ppT>(crs1.tau_powers_g1),
            libff::G2_vector<ppT>(crs1.tau_powers_g2),
            libff::G1_vector<ppT>(crs1.alpha_tau_powers_g1),
            libff::G1_vector<ppT>(crs1.beta_tau_powers_g1),
            crs1.beta_g2 + G2::one(),
            crs1.delta_g1,
            crs1.delta_g2);

        ASSERT_FALSE(r1cs_gg_ppzksnark_crs1_validate(tamper_beta_g2, n));
    }

    {
        const r1cs_gg_ppzksnark_crs1<ppT> tamper_delta_g1(
            libff::G1_vector<ppT>(crs1.tau_powers_g1),
            libff::G2_vector<ppT>(crs1.tau_powers_g2),
            libff::G1_vector<ppT>(crs1.alpha_tau_powers_g1),
            libff::G1_vector<ppT>(crs1.beta_tau_powers_g1),
            crs1.beta_g2,
            crs1.delta_g1 + G1::one(),
            crs1.delta_g2);

        ASSERT_FALSE(r1cs_gg_ppzksnark_crs1_validate(tamper_delta_g1, n));
    }

    {
        const r1cs_gg_ppzksnark_crs1<ppT> tamper_delta_g2(
            libff::G1_vector<ppT>(crs1.tau_powers_g1),
            libff::G2_vector<ppT>(crs1.tau_powers_g2),
            libff::G1_vector<ppT>(crs1.alpha_tau_powers_g1),
            libff::G1_vector<ppT>(crs1.beta_tau_powers_g1),
            crs1.beta_g2,
            crs1.delta_g1,
            crs1.delta_g2 + G2::one());

        ASSERT_FALSE(r1cs_gg_ppzksnark_crs1_validate(tamper_delta_g2, n));
    }
}

} // namespace


int main(int argc, char **argv)
{
    // !!! WARNING: Do not forget to do this once for all tests !!!
    ppT::init_public_params();
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
