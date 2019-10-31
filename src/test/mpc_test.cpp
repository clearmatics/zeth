#include "circuit-wrapper.hpp"
#include "circuits/sha256/sha256_ethereum.hpp"
#include "snarks/groth16/evaluator_from_lagrange.hpp"
#include "snarks/groth16/mpc_phase2.hpp"
#include "snarks/groth16/mpc_utils.hpp"
#include "snarks/groth16/multi_exp.hpp"
#include "snarks/groth16/powersoftau_utils.hpp"
#include "test/simple_test.hpp"
#include "util.hpp"

#include <fstream>
#include <gtest/gtest.h>
#include <thread>

using namespace libsnark;

using Fr = libff::Fr<ppT>;
using G1 = libff::G1<ppT>;
using G2 = libff::G2<ppT>;

namespace
{

static r1cs_constraint_system<Fr> get_simple_constraint_system()
{
    protoboard<Fr> pb;
    libzeth::test::simple_circuit<Fr>(pb);
    r1cs_constraint_system<Fr> cs = pb.get_constraint_system();
    cs.swap_AB_if_beneficial();
    return cs;
}

// (Deterministic) creation of accumulator
template<typename ppT>
static srs_mpc_phase2_accumulator<ppT> dummy_initial_accumulator(
    libff::Fr<ppT> seed, size_t degree, size_t num_L_elements)
{
    libff::G1_vector<ppT> H_g1(degree - 1);
    for (libff::G1<ppT> &h : H_g1) {
        h = seed * libff::G1<ppT>::one();
        seed = seed + libff::Fr<ppT>::one();
    };

    libff::G1_vector<ppT> L_g1(num_L_elements);
    for (libff::G1<ppT> &l : L_g1) {
        l = seed * libff::G1<ppT>::one();
        seed = seed + libff::Fr<ppT>::one();
    };

    return srs_mpc_phase2_accumulator<ppT>(
        libff::G1<ppT>::one(),
        libff::G2<ppT>::one(),
        std::move(H_g1),
        std::move(L_g1));
}

TEST(MPCTests, LinearCombination)
{
    // Compute the small test qap first, in order to extract the
    // degree.
    const r1cs_constraint_system<Fr> constraint_system =
        get_simple_constraint_system();
    qap_instance<Fr> qap = r1cs_to_qap_instance_map(constraint_system, true);

    // dummy powersoftau
    Fr tau = Fr::random_element();
    Fr alpha = Fr::random_element();
    Fr beta = Fr::random_element();
    const srs_powersoftau<ppT> pot =
        dummy_powersoftau_from_secrets<ppT>(tau, alpha, beta, qap.degree());
    const srs_lagrange_evaluations<ppT> lagrange =
        powersoftau_compute_lagrange_evaluations(pot, qap.degree());

    // linear combination
    const srs_mpc_layer_L1<ppT> layer1 =
        mpc_compute_linearcombination<ppT>(pot, lagrange, qap);

    // Checks that can be performed without knowledge of tau. (ratio
    // of terms in [ t(x) . x^i ]_1, etc).
    const size_t qap_n = qap.degree();
    ASSERT_EQ(qap_n, layer1.degree());
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
    //   [ beta . A_i(tau) + alpha . B_i(tau) + C_i(tau) ]_1 =
    //     layer1.ABC_g1[i]
    {
        const qap_instance_evaluation<Fr> qap_evaluation = ([&tau] {
            protoboard<Fr> pb;
            libzeth::test::simple_circuit<Fr>(pb);
            r1cs_constraint_system<Fr> constraint_system =
                pb.get_constraint_system();
            constraint_system.swap_AB_if_beneficial();
            return r1cs_to_qap_instance_map_with_evaluation(
                constraint_system, tau, true);
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

TEST(MPCTests, LinearCombinationReadWrite)
{
    const r1cs_constraint_system<Fr> constraint_system =
        get_simple_constraint_system();
    qap_instance<Fr> qap = r1cs_to_qap_instance_map(constraint_system, true);
    const srs_powersoftau<ppT> pot = dummy_powersoftau<ppT>(qap.degree());
    const srs_lagrange_evaluations<ppT> lagrange =
        powersoftau_compute_lagrange_evaluations<ppT>(pot, qap.degree());
    const srs_mpc_layer_L1<ppT> layer1 =
        mpc_compute_linearcombination<ppT>(pot, lagrange, qap);

    std::string layer1_serialized;
    {
        std::ostringstream out;
        layer1.write(out);
        layer1_serialized = out.str();
    }

    srs_mpc_layer_L1<ppT> layer1_deserialized = [layer1_serialized]() {
        std::istringstream in(layer1_serialized);
        in.exceptions(
            std::ios_base::eofbit | std::ios_base::badbit |
            std::ios_base::failbit);
        return srs_mpc_layer_L1<ppT>::read(in);
    }();

    ASSERT_EQ(layer1.T_tau_powers_g1, layer1_deserialized.T_tau_powers_g1);
    ASSERT_EQ(layer1.A_g1, layer1_deserialized.A_g1);
    ASSERT_EQ(layer1.B_g1, layer1_deserialized.B_g1);
    ASSERT_EQ(layer1.B_g2, layer1_deserialized.B_g2);
    ASSERT_EQ(layer1.ABC_g1, layer1_deserialized.ABC_g1);
}

TEST(MPCTests, Layer2)
{
    // Small test circuit and QAP
    protoboard<Fr> pb;
    libzeth::test::simple_circuit<Fr>(pb);
    r1cs_constraint_system<Fr> constraint_system = pb.get_constraint_system();
    constraint_system.swap_AB_if_beneficial();
    qap_instance<Fr> qap = r1cs_to_qap_instance_map(constraint_system, true);

    const size_t n = qap.degree();
    const Fr tau = Fr::random_element();
    const Fr alpha = Fr::random_element();
    const Fr beta = Fr::random_element();
    const Fr delta = Fr::random_element();
    const G1 g1_generator = G1::one();
    const G2 g2_generator = G2::one();

    // dummy POT and pre-compute lagrange evaluations
    srs_powersoftau<ppT> pot =
        dummy_powersoftau_from_secrets<ppT>(tau, alpha, beta, n);
    const srs_lagrange_evaluations<ppT> lagrange =
        powersoftau_compute_lagrange_evaluations(pot, n);

    // dummy circuit and layer L1
    size_t num_variables = qap.num_variables();
    size_t num_inputs = qap.num_inputs();

    srs_mpc_layer_L1<ppT> layer1 =
        mpc_compute_linearcombination<ppT>(pot, lagrange, qap);

    // layer C2
    srs_mpc_layer_C2<ppT> layer2 =
        mpc_dummy_layer_C2<ppT>(layer1, delta, num_inputs);

    // final keypair
    const r1cs_gg_ppzksnark_keypair<ppT> keypair = mpc_create_key_pair(
        std::move(pot),
        std::move(layer1),
        std::move(layer2),
        std::move(constraint_system),
        qap);

    // Compare against directly computed values
    {
        const qap_instance_evaluation<Fr> qap_evaluation = ([&tau] {
            protoboard<Fr> pb;
            libzeth::test::simple_circuit<Fr>(pb);
            r1cs_constraint_system<Fr> constraint_system =
                pb.get_constraint_system();
            constraint_system.swap_AB_if_beneficial();
            return r1cs_to_qap_instance_map_with_evaluation(
                constraint_system, tau, true);
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
                g2_generator,
                true);

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
            r1cs_gg_ppzksnark_prover(keypair.pk, primary, auxiliary, true);
        ASSERT_TRUE(
            r1cs_gg_ppzksnark_verifier_strong_IC(keypair.vk, primary, proof));
    }
}

TEST(MPCTests, LayerC2ReadWrite)
{
    const r1cs_constraint_system<Fr> constraint_system =
        get_simple_constraint_system();
    qap_instance<Fr> qap = r1cs_to_qap_instance_map(constraint_system, true);
    const srs_powersoftau<ppT> pot = dummy_powersoftau<ppT>(qap.degree());
    const srs_lagrange_evaluations<ppT> lagrange =
        powersoftau_compute_lagrange_evaluations(pot, qap.degree());
    const srs_mpc_layer_L1<ppT> layer1 =
        mpc_compute_linearcombination<ppT>(pot, lagrange, qap);
    const Fr delta = Fr::random_element();
    const srs_mpc_layer_C2<ppT> layer2 =
        mpc_dummy_layer_C2(layer1, delta, qap.num_inputs());

    std::string layer2_serialized;
    {
        std::ostringstream out;
        layer2.write(out);
        layer2_serialized = out.str();
    }

    srs_mpc_layer_C2<ppT> layer2_deserialized = [&layer2_serialized]() {
        std::istringstream in(layer2_serialized);
        in.exceptions(
            std::ios_base::eofbit | std::ios_base::badbit |
            std::ios_base::failbit);
        return srs_mpc_layer_C2<ppT>::read(in);
    }();

    ASSERT_EQ(layer2.delta_g1, layer2_deserialized.delta_g1);
    ASSERT_EQ(layer2.delta_g2, layer2_deserialized.delta_g2);
    ASSERT_EQ(layer2.H_g1, layer2_deserialized.H_g1);
    ASSERT_EQ(layer2.L_g1, layer2_deserialized.L_g1);
}

TEST(MPCTests, KeyPairReadWrite)
{
    r1cs_constraint_system<Fr> constraint_system =
        get_simple_constraint_system();
    qap_instance<Fr> qap = r1cs_to_qap_instance_map(constraint_system, true);
    srs_powersoftau<ppT> pot = dummy_powersoftau<ppT>(qap.degree());
    const srs_lagrange_evaluations<ppT> lagrange =
        powersoftau_compute_lagrange_evaluations(pot, qap.degree());
    srs_mpc_layer_L1<ppT> layer1 =
        mpc_compute_linearcombination<ppT>(pot, lagrange, qap);
    const Fr delta = Fr::random_element();
    srs_mpc_layer_C2<ppT> layer2 =
        mpc_dummy_layer_C2<ppT>(layer1, delta, qap.num_inputs());
    const r1cs_gg_ppzksnark_keypair<ppT> keypair = mpc_create_key_pair(
        std::move(pot),
        std::move(layer1),
        std::move(layer2),
        std::move(constraint_system),
        qap);

    std::string keypair_serialized;
    {
        std::ostringstream out;
        mpc_write_keypair(out, keypair);
        keypair_serialized = out.str();
    }

    r1cs_gg_ppzksnark_keypair<ppT> keypair_deserialized = [&]() {
        std::istringstream in(keypair_serialized);
        in.exceptions(
            std::ios_base::eofbit | std::ios_base::badbit |
            std::ios_base::failbit);
        return mpc_read_keypair<ppT>(in);
    }();

    ASSERT_EQ(keypair.pk, keypair_deserialized.pk);
    ASSERT_EQ(keypair.vk, keypair_deserialized.vk);
}

TEST(MPCTests, HashInterface)
{
    // in: ""
    // out: 786a....be2ce
    {
        uint8_t empty[0];
        srs_mpc_hash_t hash;
        srs_mpc_compute_hash(hash, empty, 0);
        ASSERT_EQ(
            binary_str_to_hexadecimal_str((const char *)(&hash), sizeof(hash)),
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d2"
            "5e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce");
    }

    // in: "The quick brown fox jumps over the lazy dog"
    // out: a8ad....a918
    const std::string s = "The quick brown fox jumps over the lazy dog";
    const std::string expect_hash_hex =
        "a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673f82401"
        "cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918";
    {
        srs_mpc_hash_t hash;
        srs_mpc_compute_hash(hash, s);
        ASSERT_EQ(
            expect_hash_hex,
            binary_str_to_hexadecimal_str((const char *)(&hash), sizeof(hash)));
    }
    {
        srs_mpc_hash_t hash;
        hash_ostream hs;
        hs << s;
        hs.get_hash(hash);
        ASSERT_EQ(
            expect_hash_hex,
            binary_str_to_hexadecimal_str((const char *)(&hash), sizeof(hash)));
    }
}

TEST(MPCTests, Phase2PublicKeyReadWrite)
{
    srs_mpc_hash_t empty_hash;
    const uint8_t empty[0]{};
    srs_mpc_compute_hash(empty_hash, empty, 0);

    const size_t seed = 9;
    const libff::Fr<ppT> secret_1 = libff::Fr<ppT>(seed - 1);
    const srs_mpc_phase2_publickey<ppT> pubkey =
        srs_mpc_phase2_compute_public_key<ppT>(empty_hash, G1::one(), secret_1);

    std::string pubkey_serialized;
    {
        std::ostringstream out;
        pubkey.write(out);
        pubkey_serialized = out.str();
    }

    srs_mpc_phase2_publickey<ppT> pubkey_deserialized = [&]() {
        std::istringstream in(pubkey_serialized);
        in.exceptions(
            std::ios_base::eofbit | std::ios_base::badbit |
            std::ios_base::failbit);
        return srs_mpc_phase2_publickey<ppT>::read(in);
    }();

    ASSERT_EQ(pubkey, pubkey_deserialized);
}

TEST(MPCTests, Phase2AccumulatorReadWrite)
{
    const size_t seed = 9;
    const size_t degree = 16;
    const size_t num_L_elements = 7;
    const srs_mpc_phase2_accumulator<ppT> accumulator =
        dummy_initial_accumulator<ppT>(
            libff::Fr<ppT>(seed), degree, num_L_elements);

    std::string accumulator_serialized;
    {
        std::ostringstream out;
        accumulator.write(out);
        accumulator_serialized = out.str();
    }

    srs_mpc_phase2_accumulator<ppT> accumulator_deserialized = [&]() {
        std::istringstream in(accumulator_serialized);
        in.exceptions(
            std::ios_base::eofbit | std::ios_base::badbit |
            std::ios_base::failbit);
        return srs_mpc_phase2_accumulator<ppT>::read(in);
    }();

    ASSERT_EQ(accumulator, accumulator_deserialized);
}

TEST(MPCTests, Phase2ChallengeReadWrite)
{
    const size_t seed = 9;
    const size_t degree = 16;
    const size_t num_L_elements = 7;
    const srs_mpc_phase2_challenge<ppT> challenge =
        srs_mpc_phase2_initial_challenge(dummy_initial_accumulator<ppT>(
            libff::Fr<ppT>(seed), degree, num_L_elements));

    std::string challenge_serialized;
    {
        std::ostringstream out;
        challenge.write(out);
        challenge_serialized = out.str();
    }

    srs_mpc_phase2_challenge<ppT> challenge_deserialized = [&]() {
        std::istringstream in(challenge_serialized);
        in.exceptions(
            std::ios_base::eofbit | std::ios_base::badbit |
            std::ios_base::failbit);
        return srs_mpc_phase2_challenge<ppT>::read(in);
    }();

    ASSERT_EQ(
        0,
        memcmp(
            challenge.transcript_digest,
            challenge_deserialized.transcript_digest,
            sizeof(srs_mpc_hash_t)));
    ASSERT_EQ(challenge.accumulator, challenge_deserialized.accumulator);
    ASSERT_EQ(challenge, challenge_deserialized);
}

TEST(MPCTests, Phase2ResponseReadWrite)
{
    const size_t seed = 9;
    const size_t degree = 16;
    const size_t num_L_elements = 7;
    const srs_mpc_phase2_challenge<ppT> challenge =
        srs_mpc_phase2_initial_challenge(dummy_initial_accumulator<ppT>(
            libff::Fr<ppT>(seed), degree, num_L_elements));
    const libff::Fr<ppT> secret = libff::Fr<ppT>(seed - 1);
    const srs_mpc_phase2_response<ppT> response =
        srs_mpc_phase2_compute_response<ppT>(challenge, secret);

    std::string response_serialized;
    {
        std::ostringstream out;
        response.write(out);
        response_serialized = out.str();
    }

    srs_mpc_phase2_response<ppT> response_deserialized = [&]() {
        std::istringstream in(response_serialized);
        in.exceptions(
            std::ios_base::eofbit | std::ios_base::badbit |
            std::ios_base::failbit);
        return srs_mpc_phase2_response<ppT>::read(in);
    }();

    ASSERT_EQ(response, response_deserialized);
}

TEST(MPCTests, Phase2Accumulation)
{
    const size_t seed = 9;
    const size_t degree = 16;
    const size_t num_L_elements = 7;

    // Initial challenge

    const srs_mpc_phase2_challenge<ppT> challenge_0 =
        srs_mpc_phase2_initial_challenge(dummy_initial_accumulator<ppT>(
            libff::Fr<ppT>(seed), degree, num_L_elements));

    // Participant 1
    const libff::Fr<ppT> secret_1 = libff::Fr<ppT>(seed - 1);
    srs_mpc_phase2_response<ppT> response_1 =
        srs_mpc_phase2_compute_response<ppT>(challenge_0, secret_1);
    ASSERT_TRUE(srs_mpc_phase2_verify_response(challenge_0, response_1));
    const srs_mpc_phase2_challenge<ppT> challenge_1 =
        srs_mpc_phase2_compute_challenge<ppT>(std::move(response_1));

    // Participant 2
    const libff::Fr<ppT> secret_2 = libff::Fr<ppT>(seed - 2);
    const srs_mpc_phase2_response<ppT> response_2 =
        srs_mpc_phase2_compute_response<ppT>(challenge_1, secret_2);
    ASSERT_TRUE(srs_mpc_phase2_verify_response(challenge_1, response_2));

    // Verify the size ratio of final accumulator against the original.
    const srs_mpc_phase2_accumulator<ppT> &init_accum = challenge_0.accumulator;
    const srs_mpc_phase2_accumulator<ppT> &final_accum =
        response_2.new_accumulator;
    const libff::Fr<ppT> expect_delta((seed - 1) * (seed - 2));
    const libff::Fr<ppT> expect_delta_inv = expect_delta.inverse();

    ASSERT_EQ(expect_delta * libff::G1<ppT>::one(), final_accum.delta_g1);
    ASSERT_EQ(expect_delta * libff::G2<ppT>::one(), final_accum.delta_g2);
    ASSERT_EQ(init_accum.H_g1.size(), final_accum.H_g1.size());
    for (size_t i = 0; i < init_accum.H_g1.size(); ++i) {
        ASSERT_EQ(expect_delta_inv * init_accum.H_g1[i], final_accum.H_g1[i]);
    }
    ASSERT_EQ(init_accum.L_g1.size(), final_accum.L_g1.size());
    for (size_t i = 0; i < init_accum.L_g1.size(); ++i) {
        ASSERT_EQ(expect_delta_inv * init_accum.L_g1[i], final_accum.L_g1[i]);
    }
}

TEST(MPCTests, Phase2HashToG2)
{
    // Check that independently created source values (at different locations
    // in memory) give the same result.
    const size_t seed = 9;
    const G1 s_0 = Fr(seed - 1) * G1::one();
    const G1 s_1 = Fr(seed - 1) * G1::one();
    const G1 s_delta_j_0 = Fr(seed - 2) * s_0;
    const G1 s_delta_j_1 = Fr(seed - 2) * s_1;
    const uint8_t empty[0]{};
    srs_mpc_hash_t hash_0;
    srs_mpc_compute_hash(hash_0, empty, 0);
    srs_mpc_hash_t hash_1;
    srs_mpc_compute_hash(hash_1, empty, 0);

    G2 g2_0 = srs_mpc_compute_r_g2<ppT>(s_0, s_delta_j_0, hash_0);
    G2 g2_1 = srs_mpc_compute_r_g2<ppT>(s_1, s_delta_j_1, hash_1);
    ASSERT_EQ(g2_0, g2_1);
}

TEST(MPCTests, Phase2PublicKeyGeneration)
{
    const size_t seed = 9;
    const libff::Fr<ppT> last_secret(seed - 1);
    const libff::Fr<ppT> secret(seed - 2);
    const uint8_t empty[0]{};
    srs_mpc_hash_t hash;
    srs_mpc_compute_hash(hash, empty, 0);

    const srs_mpc_phase2_publickey<ppT> publickey =
        srs_mpc_phase2_compute_public_key<ppT>(
            hash, last_secret * G1::one(), secret);

    const libff::G2<ppT> r_g2 =
        srs_mpc_compute_r_g2<ppT>(publickey.s_g1, publickey.s_delta_j_g1, hash);

    ASSERT_EQ(
        0, memcmp(hash, publickey.transcript_digest, sizeof(srs_mpc_hash_t)));
    ASSERT_EQ(last_secret * secret * G1::one(), publickey.new_delta_g1);
    ASSERT_EQ(secret * publickey.s_g1, publickey.s_delta_j_g1);
    ASSERT_EQ(secret * r_g2, publickey.r_delta_j_g2);
    ASSERT_TRUE(same_ratio<ppT>(
        last_secret * G1::one(),
        publickey.new_delta_g1,
        r_g2,
        publickey.r_delta_j_g2));
    ASSERT_TRUE(same_ratio<ppT>(
        publickey.s_g1, publickey.s_delta_j_g1, r_g2, publickey.r_delta_j_g2));
    ASSERT_TRUE(
        srs_mpc_phase2_verify_publickey(last_secret * G1::one(), publickey));
}

TEST(MPCTests, Phase2UpdateVerification)
{
    const size_t seed = 9;
    const size_t degree = 16;
    const size_t num_L_elements = 7;

    // Initial accumulator
    const srs_mpc_phase2_challenge<ppT> challenge(
        srs_mpc_phase2_initial_challenge(dummy_initial_accumulator<ppT>(
            libff::Fr<ppT>(seed), degree, num_L_elements)));
    const libff::Fr<ppT> secret(seed - 1);
    const libff::Fr<ppT> invalid_secret(seed - 2);
    const libff::Fr<ppT> invalid_secret_inv = invalid_secret.inverse();

    // Valid response should pass checks
    {
        srs_mpc_phase2_response<ppT> response =
            srs_mpc_phase2_compute_response(challenge, secret);
        ASSERT_EQ(
            0,
            memcmp(
                challenge.transcript_digest,
                response.publickey.transcript_digest,
                sizeof(srs_mpc_hash_t)));
        ASSERT_TRUE(srs_mpc_phase2_verify_response(challenge, response));
    }

    // Invalid publickey.transcript_digest
    {
        srs_mpc_phase2_response<ppT> response =
            srs_mpc_phase2_compute_response(challenge, secret);
        response.publickey.transcript_digest[srs_mpc_hash_array_length / 2] +=
            1;
        ASSERT_FALSE(srs_mpc_phase2_verify_response(challenge, response));
    }

    // Inconsistent publickey.new_delta_g1
    {
        srs_mpc_phase2_response<ppT> response =
            srs_mpc_phase2_compute_response(challenge, secret);
        response.publickey.new_delta_g1 = invalid_secret * G1::one();
        ASSERT_FALSE(srs_mpc_phase2_verify_response(challenge, response));
    }

    // Invalid $s * delta_j$ in proof-of-knowledge
    {
        srs_mpc_phase2_response<ppT> response =
            srs_mpc_phase2_compute_response(challenge, secret);
        response.publickey.s_delta_j_g1 =
            invalid_secret * response.publickey.s_g1;
        ASSERT_FALSE(srs_mpc_phase2_verify_response(challenge, response));
    }

    // Invalid $r * delta_j$ in proof-of-knowledge
    {
        srs_mpc_phase2_response<ppT> response =
            srs_mpc_phase2_compute_response(challenge, secret);
        const libff::G2<ppT> r_g2 = srs_mpc_compute_r_g2<ppT>(
            response.publickey.s_g1,
            response.publickey.s_delta_j_g1,
            response.publickey.transcript_digest);
        response.publickey.r_delta_j_g2 = invalid_secret * r_g2;
        ASSERT_FALSE(srs_mpc_phase2_verify_response(challenge, response));
    }

    // Inconsistent delta_1 in new accumulator
    {
        srs_mpc_phase2_response<ppT> response =
            srs_mpc_phase2_compute_response(challenge, secret);
        response.new_accumulator.delta_g1 =
            invalid_secret * libff::G1<ppT>::one();
        ASSERT_FALSE(srs_mpc_phase2_verify_response(challenge, response));
    }

    // Inconsistent delta_2 in new accumulator
    {
        srs_mpc_phase2_response<ppT> response =
            srs_mpc_phase2_compute_response(challenge, secret);
        response.new_accumulator.delta_g2 =
            invalid_secret * libff::G2<ppT>::one();
        ASSERT_FALSE(srs_mpc_phase2_verify_response(challenge, response));
    }

    // Inconsistent delta_G2, H_i
    {
        const size_t invalidate_idx = degree / 2;
        srs_mpc_phase2_response<ppT> response =
            srs_mpc_phase2_compute_response(challenge, secret);
        response.new_accumulator.H_g1[invalidate_idx] =
            invalid_secret_inv * challenge.accumulator.H_g1[invalidate_idx];
        ASSERT_FALSE(srs_mpc_phase2_verify_response(challenge, response));
    }

    // Inconsistent delta_G2, L_i
    {
        const size_t invalidate_idx = num_L_elements / 2;
        srs_mpc_phase2_response<ppT> response =
            srs_mpc_phase2_compute_response(challenge, secret);
        response.new_accumulator.L_g1[invalidate_idx] =
            invalid_secret_inv * challenge.accumulator.L_g1[invalidate_idx];
        ASSERT_FALSE(srs_mpc_phase2_verify_response(challenge, response));
    }
}

TEST(MPCTests, Phase2TranscriptVerification)
{
    const size_t seed = 9;
    const size_t degree = 16;
    const size_t num_L_elements = 7;

    // Simulate a transcript with 3 participants.
    const srs_mpc_phase2_challenge<ppT> challenge_0 =
        srs_mpc_phase2_initial_challenge(dummy_initial_accumulator<ppT>(
            libff::Fr<ppT>(seed), degree, num_L_elements));
    std::ostringstream transcript_out;

    // Participant 1
    const libff::Fr<ppT> secret_1 = libff::Fr<ppT>(seed - 1);
    srs_mpc_phase2_response<ppT> response_1 =
        srs_mpc_phase2_compute_response<ppT>(challenge_0, secret_1);
    response_1.publickey.write(transcript_out);
    const srs_mpc_phase2_challenge<ppT> challenge_1 =
        srs_mpc_phase2_compute_challenge<ppT>(std::move(response_1));

    // Participant 2
    const libff::Fr<ppT> secret_2 = libff::Fr<ppT>(seed - 2);
    srs_mpc_phase2_response<ppT> response_2 =
        srs_mpc_phase2_compute_response<ppT>(challenge_1, secret_2);
    response_2.publickey.write(transcript_out);
    const srs_mpc_phase2_challenge<ppT> challenge_2 =
        srs_mpc_phase2_compute_challenge<ppT>(std::move(response_2));

    // Participant 3
    const libff::Fr<ppT> secret_3 = libff::Fr<ppT>(seed - 3);
    const srs_mpc_phase2_response<ppT> response_3 =
        srs_mpc_phase2_compute_response<ppT>(challenge_2, secret_3);
    response_3.publickey.write(transcript_out);

    // Create a transcript and verify it.
    std::istringstream transcript(transcript_out.str());
    G1 final_delta_g1;
    ASSERT_TRUE(srs_mpc_phase2_verify_transcript<ppT>(
        challenge_0.transcript_digest, G1::one(), transcript, final_delta_g1));
    ASSERT_EQ(secret_1 * secret_2 * secret_3 * G1::one(), final_delta_g1);
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
