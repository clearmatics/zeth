#include "snarks/groth16/mpc_utils.hpp"
#include "snarks/groth16/multi_exp.hpp"
#include "test/simple_test.hpp"
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

TEST(MPCTests, LinearCombination)
{
    // Compute the small test qap first, in order to extract the
    // degree.
    const r1cs_constraint_system<Fr> constraint_system = ([] {
        protoboard<Fr> pb;
        libzeth::test::simple_circuit<Fr>(pb);
        r1cs_constraint_system<Fr> cs = pb.get_constraint_system();
        cs.swap_AB_if_beneficial();
        return cs;
    })();
    qap_instance<Fr> qap = r1cs_to_qap_instance_map(constraint_system);

    // dummy powersoftau
    Fr tau = Fr::random_element();
    Fr alpha = Fr::random_element();
    Fr beta = Fr::random_element();
    const srs_powersoftau pot =
        dummy_powersoftau_from_secrets(tau, alpha, beta, qap.degree());

    // linear combination
    const srs_mpc_layer_L1<ppT> layer1 =
        mpc_compute_linearcombination<ppT>(pot, qap);

    // Without knowlege of tau, not many checks can be performed
    // beyond the ratio of terms in [ t(x) . x^i ]_1.
    const size_t qap_n = qap.degree();
    ASSERT_EQ(qap_n - 1, layer1.T_tau_powers_g1.size());
    ASSERT_EQ(qap.num_variables() + 1, layer1.ABC_g1.size());

    for (size_t i = 1; i < qap_n - 1; ++i) {
        ASSERT_TRUE(::same_ratio<ppT>(
            layer1.T_tau_powers_g1[i - 1],
            layer1.T_tau_powers_g1[i],
            pot.tau_powers_g2[0],
            pot.tau_powers_g2[1]))
            << "i = " << std::to_string(i);
    }

    // Use knowledge of secrets to confirm values.
    // Check that:
    //
    //   [ domain.Z(tau) ]_1 = layer1.T_tau_powers_g1[0]
    //   [ beta . A_i(tau) + alpha . B_i(tau) + C_i(tau) ]_1 = layer1.ABC_g1[i]
    {
        const qap_instance_evaluation<Fr> qap_evaluation = ([&tau] {
            protoboard<Fr> pb;
            libzeth::test::simple_circuit<Fr>(pb);
            r1cs_constraint_system<Fr> constraint_system =
                pb.get_constraint_system();
            constraint_system.swap_AB_if_beneficial();
            return r1cs_to_qap_instance_map_with_evaluation(
                constraint_system, tau);
        })();

        ASSERT_EQ(
            qap_evaluation.domain->compute_vanishing_polynomial(tau) *
                G1::one(),
            layer1.T_tau_powers_g1[0]);

        for (size_t i = 0; i < qap_evaluation.num_variables() + 1; ++i) {
            // At
            ASSERT_EQ(qap_evaluation.At[i] * G1::one(), layer1.A_g1[i]);

            // Bt
            ASSERT_EQ(qap_evaluation.Bt[i] * G1::one(), layer1.B_g1[i]);
            ASSERT_EQ(qap_evaluation.Bt[i] * G2::one(), layer1.B_g2[i]);

            // ABCt
            const Fr ABC_i = beta * qap_evaluation.At[i] +
                             alpha * qap_evaluation.Bt[i] +
                             qap_evaluation.Ct[i];
            ASSERT_EQ(ABC_i * G1::one(), layer1.ABC_g1[i]);
        }
    }
}

TEST(MPCTests, Layer2)
{
    // Choose n to be a power of 2 greater than degree of the QAP.
    const size_t n = 16;
    const Fr tau = Fr::random_element();
    const Fr alpha = Fr::random_element();
    const Fr beta = Fr::random_element();
    const Fr delta = Fr::random_element();
    const G1 g1_generator = G1::one();
    const G2 g2_generator = G2::one();

    // dummy CRS1
    srs_powersoftau pot = dummy_powersoftau_from_secrets(tau, alpha, beta, n);

    // dummy circuit and Layer1
    protoboard<Fr> pb;
    libzeth::test::simple_circuit<Fr>(pb);
    r1cs_constraint_system<Fr> constraint_system = pb.get_constraint_system();
    qap_instance<Fr> qap = r1cs_to_qap_instance_map(constraint_system);
    ASSERT_TRUE(qap.degree() <= n) << "Test QAP has degree too high";

    size_t num_variables = qap.num_variables();
    size_t num_inputs = qap.num_inputs();

    srs_mpc_layer_L1<ppT> layer1 = mpc_compute_linearcombination<ppT>(pot, qap);

    // Final key pair
    const r1cs_gg_ppzksnark_keypair<ppT> keypair = mpc_dummy_layer2(
        std::move(pot),
        std::move(layer1),
        delta,
        std::move(constraint_system),
        qap);

    // Compare against directly computed values
    {
        const qap_instance_evaluation<Fr> qap_evaluation = ([&tau] {
            protoboard<Fr> pb;
            libzeth::test::simple_circuit<Fr>(pb);
            const r1cs_constraint_system<Fr> constraint_system =
                pb.get_constraint_system();
            return r1cs_to_qap_instance_map_with_evaluation(
                constraint_system, tau);
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
        Fr t_x_i = qap_evaluation.domain->compute_vanishing_polynomial(tau) *
                   delta_inverse;
        for (size_t i = 0; i < pk.H_query.size(); ++i) {
            ASSERT_EQ(t_x_i * G1::one(), pk.H_query[i])
                << "i = " << std::to_string(i);
            t_x_i = tau * t_x_i;
        }

        // L_query
        ASSERT_EQ(num_variables - num_inputs, pk.L_query.size());
        for (size_t i = 0; i < num_variables - num_inputs; ++i) {
            // index into qap_evaluation
            const size_t j = i + num_inputs + 1;

            // ABC / delta
            const Fr ABC_j_over_delta =
                (beta * qap_evaluation.At[j] + alpha * qap_evaluation.Bt[j] +
                 qap_evaluation.Ct[j]) *
                delta_inverse;
            ASSERT_EQ(ABC_j_over_delta * G1::one(), pk.L_query[i])
                << "i = " << std::to_string(i);
        }

        // Test Verification Key
        const r1cs_gg_ppzksnark_verification_key<ppT> &vk = keypair.vk;
        ASSERT_EQ(alpha * G1::one(), vk.alpha_g1);
        ASSERT_EQ(beta * G2::one(), vk.beta_g2);
        ASSERT_EQ(delta * G2::one(), vk.delta_g2);
        ASSERT_EQ(num_inputs, vk.ABC_g1.domain_size());

        const Fr ABC_0 = beta * qap_evaluation.At[0] +
                         alpha * qap_evaluation.Bt[0] + qap_evaluation.Ct[0];
        ASSERT_EQ(ABC_0 * G1::one(), vk.ABC_g1.first);
        for (size_t i = 1; i < vk.ABC_g1.size(); ++i) {
            const Fr ABC_i = beta * qap_evaluation.At[i] +
                             alpha * qap_evaluation.Bt[i] +
                             qap_evaluation.Ct[i];
            ASSERT_EQ(ABC_i * G1::one(), vk.ABC_g1.rest[i - 1]);
        }
    }

    // Compare with key_pair generated directly from the same secrets.
    {
        const r1cs_constraint_system<Fr> constraint_system = ([&] {
            protoboard<Fr> pb;
            libzeth::test::simple_circuit<Fr>(pb);
            r1cs_constraint_system<Fr> cs = pb.get_constraint_system();
            cs.swap_AB_if_beneficial();
            return cs;
        })();

        const r1cs_gg_ppzksnark_keypair<ppT> keypair2 =
            r1cs_gg_ppzksnark_generator_from_secrets<ppT>(
                constraint_system,
                tau,
                alpha,
                beta,
                delta,
                g1_generator,
                g2_generator);

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
        const r1cs_primary_input<Fr> primary{12};
        const r1cs_auxiliary_input<Fr> auxiliary{1, 1, 1};
        const r1cs_gg_ppzksnark_proof<ppT> proof =
            r1cs_gg_ppzksnark_prover(keypair.pk, primary, auxiliary);
        ASSERT_TRUE(
            r1cs_gg_ppzksnark_verifier_strong_IC(keypair.vk, primary, proof));
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
