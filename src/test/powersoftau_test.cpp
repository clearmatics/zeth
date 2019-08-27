
#include "snarks/groth16/powersoftau_utils.hpp"
#include "util.hpp"

#include <gtest/gtest.h>

using ppT = libff::default_ec_pp;
using Fr = libff::Fr<ppT>;
using G1 = libff::G1<ppT>;
using G2 = libff::G2<ppT>;
using namespace libsnark;
using namespace libzeth;

namespace
{

TEST(PowersOfTauTests, PowersOfTauValidation)
{
    const size_t n = 16;
    const srs_powersoftau pot = dummy_powersoftau(n);

    ASSERT_TRUE(powersoftau_validate(pot, n));

    // tamper with some individual entries

    {
        libff::G1_vector<ppT> tau_powers_g1 = pot.tau_powers_g1;
        tau_powers_g1[2] = tau_powers_g1[2] + G1::one();
        const srs_powersoftau tamper_tau_g1(
            std::move(tau_powers_g1),
            libff::G2_vector<ppT>(pot.tau_powers_g2),
            libff::G1_vector<ppT>(pot.alpha_tau_powers_g1),
            libff::G1_vector<ppT>(pot.beta_tau_powers_g1),
            pot.beta_g2);

        ASSERT_FALSE(powersoftau_validate(tamper_tau_g1, n));
    }

    {
        libff::G2_vector<ppT> tau_powers_g2 = pot.tau_powers_g2;
        tau_powers_g2[2] = tau_powers_g2[2] + G2::one();
        const srs_powersoftau tamper_tau_g2(
            libff::G1_vector<ppT>(pot.tau_powers_g1),
            std::move(tau_powers_g2),
            libff::G1_vector<ppT>(pot.alpha_tau_powers_g1),
            libff::G1_vector<ppT>(pot.beta_tau_powers_g1),
            pot.beta_g2);

        ASSERT_FALSE(powersoftau_validate(tamper_tau_g2, n));
    }

    {
        libff::G1_vector<ppT> alpha_tau_powers_g1 = pot.alpha_tau_powers_g1;
        alpha_tau_powers_g1[2] = alpha_tau_powers_g1[2] + G1::one();
        const srs_powersoftau tamper_alpha_tau_g1(
            libff::G1_vector<ppT>(pot.tau_powers_g1),
            libff::G2_vector<ppT>(pot.tau_powers_g2),
            std::move(alpha_tau_powers_g1),
            libff::G1_vector<ppT>(pot.beta_tau_powers_g1),
            pot.beta_g2);

        ASSERT_FALSE(powersoftau_validate(tamper_alpha_tau_g1, n));
    }

    {
        libff::G1_vector<ppT> beta_tau_powers_g1 = pot.beta_tau_powers_g1;
        beta_tau_powers_g1[2] = beta_tau_powers_g1[2] + G1::one();
        const srs_powersoftau tamper_beta_tau_g1(
            libff::G1_vector<ppT>(pot.tau_powers_g1),
            libff::G2_vector<ppT>(pot.tau_powers_g2),
            libff::G1_vector<ppT>(pot.alpha_tau_powers_g1),
            std::move(beta_tau_powers_g1),
            pot.beta_g2);

        ASSERT_FALSE(powersoftau_validate(tamper_beta_tau_g1, n));
    }

    {
        const srs_powersoftau tamper_beta_g2(
            libff::G1_vector<ppT>(pot.tau_powers_g1),
            libff::G2_vector<ppT>(pot.tau_powers_g2),
            libff::G1_vector<ppT>(pot.alpha_tau_powers_g1),
            libff::G1_vector<ppT>(pot.beta_tau_powers_g1),
            pot.beta_g2 + G2::one());

        ASSERT_FALSE(powersoftau_validate(tamper_beta_g2, n));
    }
}

} // namespace

int main(int argc, char **argv)
{
    // !!! WARNING: Do not forget to do this once for all tests !!!
    ppT::init_public_params();

    // Remove stdout noise from libff
    libff::inhibit_profiling_counters = true;
    libff::inhibit_profiling_info = true;

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
