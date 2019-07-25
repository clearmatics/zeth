
#include "snarks/groth16/crs.hpp"
#include "test/simple_test.hpp"

#include <gtest/gtest.h>

using ppT = libff::default_ec_pp;
using Fr = libff::Fr<ppT>;
using G1 = libff::G1<ppT>;
using G2 = libff::G2<ppT>;
using namespace libsnark;

namespace zeth
{
namespace test
{

// Given some secrets, compute a dummy set of powers-of-tau, for
// circuits with polynomials A, B, C order-bound by `n` .
r1cs_gg_ppzksnark_crs1<ppT> dummy_phase1_from_secrets(
    const Fr &tau,
    const Fr &alpha,
    const Fr &beta,
    const Fr &delta,
    size_t n)
{
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

// Same as dummy_phase1_from_secrets(), where the secrets are not of
// interest.
r1cs_gg_ppzksnark_crs1<ppT> dummy_phase1(size_t n)
{
    Fr tau = Fr::random_element();
    Fr alpha = Fr::random_element();
    Fr beta = Fr::random_element();
    Fr delta = Fr::random_element();

    return dummy_phase1_from_secrets(tau, alpha, beta, delta, n);
}


TEST(CRSTests, CRS1Validation)
{
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


TEST(CRSTests, Phase2)
{
    const size_t n = 16;

    // dummy phase 1

    Fr tau = Fr::random_element();
    Fr alpha = Fr::random_element();
    Fr beta = Fr::random_element();
    Fr delta = Fr::random_element();
    const r1cs_gg_ppzksnark_crs1<ppT> crs1 = zeth::test::dummy_phase1_from_secrets(
        tau, alpha, beta, delta, n);

    // Dummy constraint system

    protoboard<Fr> pb;
    zeth::test::simple_circuit<ppT>(pb);
    const r1cs_constraint_system<Fr> constraint_system =
        pb.get_constraint_system();

    // phase 2

    qap_instance<FieldT> qap = r1cs_to_qap_instance_map(constraint_system);
    const r1cs_gg_ppzksnark_crs2<ppT> crs2 = r1cs_gg_ppzksnark_generator_phase2(
        crs1,
        qap);

    // Without knowlege of tau, not many checks can be performed
    // beyond the ratio of terms in [ t(x) . x^i ]_1.

    const size_t qap_n = qap.degree();
    ASSERT_EQ(qap_n - 1, crs2.T_tau_powers_g1.size());
    ASSERT_EQ(qap.num_variables() + 1, crs2.ABC_g1.size());

    for (size_t i = 1 ; i < qap_n - 1 ; ++i)
    {
        ASSERT_TRUE(::same_ratio<ppT>(
            crs2.T_tau_powers_g1[i-1],
            crs2.T_tau_powers_g1[i],
            crs1.tau_powers_g2[0],
            crs1.tau_powers_g2[1]));
    }

    // Use knowledge of secrets to confirm values.
    // Check that:
    //
    //   [ domain.Z(tau) ]_1 = crs2.T_tau_powers_g1[0]
    //   [ beta . A_i(tau) + alpha . B_i(tau) + C_i(tau) ]_1 = crs2.ABC_g1[i]
}


TEST(CRSTests, Phase3)
{
    const size_t n = 16;
    const Fr tau = Fr::random_element();
    const Fr alpha = Fr::random_element();
    const Fr beta = Fr::random_element();
    const Fr delta = Fr::random_element();

    // dummy CRS2

    r1cs_gg_ppzksnark_crs1<ppT> crs1 = zeth::test::dummy_phase1_from_secrets(
        tau, alpha, beta, delta, n);

    protoboard<Fr> pb;
    zeth::test::simple_circuit<ppT>(pb);
    r1cs_constraint_system<Fr> constraint_system =
        pb.get_constraint_system();
    qap_instance<FieldT> qap = r1cs_to_qap_instance_map(constraint_system);

    r1cs_gg_ppzksnark_crs2<ppT> crs2 = r1cs_gg_ppzksnark_generator_phase2(
        crs1,
        qap);

    // Final key pair

    const r1cs_gg_ppzksnark_keypair<ppT> keypair =
        r1cs_gg_ppzksnark_generator_dummy_phase3(
            std::move(crs1),
            std::move(crs2),
            std::move(constraint_system),
            qap);

    ASSERT_EQ(alpha * G1::one(), keypair.pk.alpha_g1);
}

} // namespace test
} // namespace zeth

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
