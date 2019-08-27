#include "circuits/mimc/mimc.hpp"
#include "snarks_alias.hpp"

#include "gtest/gtest.h"
#include <libff/common/default_types/ec_pp.hpp>

using namespace libsnark;
using namespace libzeth;

typedef libff::default_ec_pp ppT;
typedef libff::Fr<ppT> FieldT;

namespace
{

TEST(TestRound, TestTrue)
{
    libsnark::protoboard<FieldT> pb;

    libsnark::pb_variable<FieldT> in_x;
    libsnark::pb_variable<FieldT> in_k;
    in_x.allocate(pb, "x");
    in_k.allocate(pb, "k");

    pb.val(in_x) = FieldT("3703141493535563179657531719960160174296085208671919"
                          "316200479060314459804651");
    pb.val(in_k) = FieldT("1568395149631190174933950911896067630329022481212975"
                          "2890706581988986633412003");

    MiMCe7_permutation_gadget<FieldT> mimc_gadget(
        pb, in_x, in_k, "mimc_gadget");
    mimc_gadget.generate_r1cs_constraints();
    mimc_gadget.generate_r1cs_witness();

    FieldT expected_out = FieldT("192990723315478049773124691205698348115617480"
                                 "95378968014959488920239255590840");
    ASSERT_TRUE(expected_out == pb.val(mimc_gadget.result()));
}

TEST(TestRound, TestFalse)
{
    libsnark::protoboard<FieldT> pb;

    libsnark::pb_variable<FieldT> in_x;
    libsnark::pb_variable<FieldT> in_k;
    in_x.allocate(pb, "x");
    in_k.allocate(pb, "k");

    pb.val(in_x) = FieldT("3703141493535563179657531719960160174296085208671919"
                          "316200479060314459804651");
    pb.val(in_k) = FieldT("13455131405143248756924738814405142");

    MiMCe7_permutation_gadget<FieldT> mimc_gadget(
        pb, in_x, in_k, "mimc_gadget");
    mimc_gadget.generate_r1cs_witness();
    mimc_gadget.generate_r1cs_constraints();

    FieldT expected_out = FieldT("114374678233937903873991372494419413137176864"
                                 "41929791910070352316474327319704");
    ASSERT_FALSE(expected_out == pb.val(mimc_gadget.result()));
}

} // namespace

int main(int argc, char **argv)
{
    ppT::init_public_params(); // /!\ WARNING: Do once for all tests. Do not
                               // forget to do this !!!!
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
