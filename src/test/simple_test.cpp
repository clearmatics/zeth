
#include "simple_test.hpp"
#include <gtest/gtest.h>

using ppT = libff::default_ec_pp;
using FieldT = libff::Fr<ppT>;
using namespace libsnark;

namespace
{

TEST(SimpleTests, SimpleCircuitProof)
{
    // Simple circuit

    protoboard<FieldT> pb;
    zeth::test::simple_circuit<ppT>(pb);

    // Constraint system

    const r1cs_constraint_system<FieldT> constraint_system =
        pb.get_constraint_system();

    const r1cs_primary_input<FieldT> primary { 12 };
    const r1cs_auxiliary_input<FieldT> auxiliary  { 1, 1, 1 };

    {
        // Test solution x = 1 (g1 = 1, g2 = 1), y = 12
        ASSERT_TRUE(constraint_system.is_satisfied(primary, auxiliary));

        const r1cs_auxiliary_input<FieldT> auxiliary_invalid[]
        {
            r1cs_auxiliary_input<FieldT> { 2, 1, 2 },
            r1cs_auxiliary_input<FieldT> { 1, 2, 2 },
            r1cs_auxiliary_input<FieldT> { 1, 1, 2 },
        };
        for (const auto &invalid : auxiliary_invalid)
        {
            ASSERT_FALSE(constraint_system.is_satisfied(primary, invalid));
        }
    }

    const r1cs_gg_ppzksnark_keypair<ppT> keypair =
        r1cs_gg_ppzksnark_generator<ppT>(constraint_system);

    // const qap_instance<FieldT> qap = r1cs_to_qap_instance_map(constraint_system);
    // printf("qap.eval_domain.m: %zu\n", qap.domain->m);

    const r1cs_gg_ppzksnark_proof<ppT> proof = r1cs_gg_ppzksnark_prover(
        keypair.pk, primary, auxiliary);

    ASSERT_TRUE(
        r1cs_gg_ppzksnark_verifier_strong_IC(keypair.vk, primary, proof));

    ASSERT_TRUE(true);
}

} // namespace


int main(int argc, char **argv)
{
    // !!! WARNING: Do not forget to do this once for all tests !!!
    ppT::init_public_params();
    // Remove stdout noise from libff
    libff::inhibit_profiling_counters = true;
    libff::inhibit_profiling_info = true;
    // Run
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
