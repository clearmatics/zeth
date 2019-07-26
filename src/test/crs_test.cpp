
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
        beta * G2::one());
}

// Same as dummy_phase1_from_secrets(), where the secrets are not of
// interest.
r1cs_gg_ppzksnark_crs1<ppT> dummy_phase1(size_t n)
{
    Fr tau = Fr::random_element();
    Fr alpha = Fr::random_element();
    Fr beta = Fr::random_element();

    return dummy_phase1_from_secrets(tau, alpha, beta, n);
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
            crs1.beta_g2);

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
            crs1.beta_g2);

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
            crs1.beta_g2);

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
            crs1.beta_g2);

        ASSERT_FALSE(r1cs_gg_ppzksnark_crs1_validate(tamper_beta_tau_g1, n));
    }

    {
        const r1cs_gg_ppzksnark_crs1<ppT> tamper_beta_g2(
            libff::G1_vector<ppT>(crs1.tau_powers_g1),
            libff::G2_vector<ppT>(crs1.tau_powers_g2),
            libff::G1_vector<ppT>(crs1.alpha_tau_powers_g1),
            libff::G1_vector<ppT>(crs1.beta_tau_powers_g1),
            crs1.beta_g2 + G2::one());

        ASSERT_FALSE(r1cs_gg_ppzksnark_crs1_validate(tamper_beta_g2, n));
    }
}


TEST(CRSTests, Phase2)
{
    const size_t n = 16;

    // dummy phase 1

    Fr tau = Fr::random_element();
    Fr alpha = Fr::random_element();
    Fr beta = Fr::random_element();
    const r1cs_gg_ppzksnark_crs1<ppT> crs1 = zeth::test::dummy_phase1_from_secrets(
        tau, alpha, beta, n);

    // Dummy constraint system

    const r1cs_constraint_system<Fr> constraint_system = ([]
    {
        protoboard<Fr> pb;
        zeth::test::simple_circuit<ppT>(pb);
        return pb.get_constraint_system();
    })();

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

    {
        const qap_instance_evaluation<Fr> qap_evaluation = ([&tau]
        {
            protoboard<Fr> pb;
            zeth::test::simple_circuit<ppT>(pb);
            const r1cs_constraint_system<Fr> constraint_system =
                pb.get_constraint_system();
            return r1cs_to_qap_instance_map_with_evaluation(constraint_system, tau);
        })();

        ASSERT_EQ(
            qap_evaluation.domain->compute_vanishing_polynomial(tau) * G1::one(),
            crs2.T_tau_powers_g1[0]);

        for (size_t i = 0 ; i < qap_evaluation.num_variables() + 1 ; ++i)
        {
            // At
            ASSERT_EQ(qap_evaluation.At[i] * G1::one(), crs2.A_g1[i]);

            // Bt
            ASSERT_EQ(qap_evaluation.Bt[i] * G1::one(), crs2.B_g1[i]);
            ASSERT_EQ(qap_evaluation.Bt[i] * G2::one(), crs2.B_g2[i]);

            // ABCt
            const Fr ABC_i =
                beta * qap_evaluation.At[i] +
                alpha * qap_evaluation.Bt[i] +
                qap_evaluation.Ct[i];
            ASSERT_EQ(ABC_i * G1::one(), crs2.ABC_g1[i]);
        }
    }
}


TEST(CRSTests, Phase3)
{
    const size_t n = 16;
    const Fr tau = Fr::random_element();
    const Fr alpha = Fr::random_element();
    const Fr beta = Fr::random_element();
    const Fr delta = Fr::random_element();
    const G1 g1_generator = G1::random_element();

    // dummy CRS1

    r1cs_gg_ppzksnark_crs1<ppT> crs1 = zeth::test::dummy_phase1_from_secrets(
        tau, alpha, beta, n);

    // dummy circuit and CRS2

    protoboard<Fr> pb;
    zeth::test::simple_circuit<ppT>(pb);
    r1cs_constraint_system<Fr> constraint_system = pb.get_constraint_system();
    qap_instance<FieldT> qap = r1cs_to_qap_instance_map(constraint_system);

    size_t num_variables = qap.num_variables();
    size_t num_inputs = qap.num_inputs();

    r1cs_gg_ppzksnark_crs2<ppT> crs2 = r1cs_gg_ppzksnark_generator_phase2(
        crs1,
        qap);

    // Final key pair

    const r1cs_gg_ppzksnark_keypair<ppT> keypair =
        r1cs_gg_ppzksnark_generator_dummy_phase3(
            std::move(crs1),
            std::move(crs2),
            delta,
            std::move(constraint_system),
            qap);

    // Compare against directly computed values

    {
        const qap_instance_evaluation<Fr> qap_evaluation = ([&tau]
        {
            protoboard<Fr> pb;
            zeth::test::simple_circuit<ppT>(pb);
            const r1cs_constraint_system<Fr> constraint_system =
                pb.get_constraint_system();
            return r1cs_to_qap_instance_map_with_evaluation(constraint_system, tau);
        })();

        const Fr delta_inverse = delta.inverse();

        // Test Proving Key

        const r1cs_gg_ppzksnark_proving_key<ppT> &pk = keypair.pk;

        ASSERT_EQ(alpha * G1::one(), pk.alpha_g1);
        ASSERT_EQ(beta * G1::one(), pk.beta_g1);
        ASSERT_EQ(beta * G2::one(), pk.beta_g2);
        ASSERT_EQ(delta * G1::one(), pk.delta_g1);
        ASSERT_EQ(delta * G2::one(), pk.delta_g2);

        // H_query

        ASSERT_EQ(qap_evaluation.degree() - 1, pk.H_query.size());
        Fr t_x_i = qap_evaluation.domain->compute_vanishing_polynomial(tau) * delta_inverse;
        for (size_t i = 0 ; i < pk.H_query.size() ; ++i)
        {
           ASSERT_EQ(t_x_i * G1::one(), pk.H_query[i])
                << "i = " << std::to_string(i);
            t_x_i = tau * t_x_i;
        }

        // L_query

        ASSERT_EQ(num_variables - num_inputs, pk.L_query.size());
        for (size_t i = 0 ; i < num_variables - num_inputs ; ++i)
        {
            const size_t j = i + num_inputs + 1; // index into qap_evaluation

            // ABC / delta
            const Fr ABC_j_over_delta =
                (beta * qap_evaluation.At[j] +
                 alpha * qap_evaluation.Bt[j] +
                 qap_evaluation.Ct[j]) * delta_inverse;
            ASSERT_EQ(ABC_j_over_delta * G1::one(), pk.L_query[i])
                << "i = " << std::to_string(i);
        }

        // Test Verification Key

        const r1cs_gg_ppzksnark_verification_key<ppT> &vk = keypair.vk;
        ASSERT_EQ(alpha * G1::one(), vk.alpha_g1);
        ASSERT_EQ(beta * G2::one(), vk.beta_g2);
        ASSERT_EQ(delta * G2::one(), vk.delta_g2);
        ASSERT_EQ(num_inputs, vk.ABC_g1.domain_size());

        const Fr ABC_0 =
            beta * qap_evaluation.At[0] +
            alpha * qap_evaluation.Bt[0] +
            qap_evaluation.Ct[0];
        ASSERT_EQ(ABC_0 * G1::one(), vk.ABC_g1.first);
        for (size_t i = 1 ; i < vk.ABC_g1.size() ; ++i)
        {
            const Fr ABC_i =
                beta * qap_evaluation.At[i] +
                alpha * qap_evaluation.Bt[i] +
                qap_evaluation.Ct[i];
            ASSERT_EQ(ABC_i * G1::one(), vk.ABC_g1.rest[i-1]);
        }
    }

    // Compare with key_pair generated directly from the same secrets.

    {
        const r1cs_constraint_system<Fr> constraint_system = ([&]
        {
            protoboard<Fr> pb;
            zeth::test::simple_circuit<ppT>(pb);
            return pb.get_constraint_system();
        })();

        const r1cs_gg_ppzksnark_keypair<ppT> keypair2 =
            r1cs_gg_ppzksnark_generator_from_secrets<ppT>(
                constraint_system, tau, alpha, beta, delta, g1_generator);

        ASSERT_EQ(keypair2.pk.alpha_g1, keypair.pk.alpha_g1);
        ASSERT_EQ(keypair2.pk.beta_g1, keypair.pk.beta_g1);
        ASSERT_EQ(keypair2.pk.beta_g2, keypair.pk.beta_g2);
        ASSERT_EQ(keypair2.pk.delta_g1, keypair.pk.delta_g1);
        ASSERT_EQ(keypair2.pk.delta_g2, keypair.pk.delta_g2);
        ASSERT_EQ(keypair2.pk.A_query, keypair.pk.A_query);
        ASSERT_EQ(keypair2.pk.B_query, keypair.pk.B_query);
        ASSERT_EQ(keypair2.pk.H_query, keypair.pk.H_query);
        ASSERT_EQ(keypair2.pk.L_query, keypair.pk.L_query);

        ASSERT_EQ(keypair2.vk, keypair.vk);
    }

    // Check that the keypair works for proving / verification

    {
        const r1cs_primary_input<FieldT> primary { 12 };
        const r1cs_auxiliary_input<FieldT> auxiliary  { 1, 1, 1 };
        const r1cs_gg_ppzksnark_proof<ppT> proof = r1cs_gg_ppzksnark_prover(
            keypair.pk, primary, auxiliary);
        ASSERT_TRUE(
            r1cs_gg_ppzksnark_verifier_strong_IC(keypair.vk, primary, proof));
    }
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
