
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdelete-non-virtual-dtor"

# include "libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp"
# include "libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp"
# include "libsnark/gadgetlib1/pb_variable.hpp"

#pragma GCC diagnostic pop

#include <gtest/gtest.h>

using ppT = libff::default_ec_pp;
using FieldT = libff::Fr<ppT>;
using namespace libsnark;

namespace
{

TEST(SimpleTests, SimpleCircuitProof)
{
    protoboard<FieldT> pb;

    // Circuit
    //
    // x^3 + 4x^2 + 2x + 5 = y

    pb_variable<FieldT> x;
    pb_variable<FieldT> y;
    pb_variable<FieldT> g1;
    pb_variable<FieldT> g2;
    // pb_variable<FieldT> g_out;

    // Statement
    y.allocate(pb, "y");

    // Witness
    x.allocate(pb, "x");
    g1.allocate(pb, "g1");
    g2.allocate(pb, "g2");

    pb.set_input_sizes(1);

    // Constraints

    //   g1
    //  /  \
    //  \  /
    //   x

    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(x, x, g1), "g1");

    //   g2
    //  /  \
    // g1   x

    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(g1, x, g2), "g2");

    //                    g_out
    //                   /     \
    //                  /       \
    // g2 + 4.g1 + 2x + 5        1

    pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(g2 + (4*g1) + (2*x) + 5, 1, y), "y");

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
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
