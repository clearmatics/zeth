#include "circuits/mimc/mimc_mp.hpp"

#include "gtest/gtest.h"
#include <libff/common/default_types/ec_pp.hpp>

using namespace libzeth;

typedef libff::default_ec_pp ppT;
typedef libff::Fr<ppT> FieldT;

namespace
{

// Testing that (15212  + 98645 + 216319)**7 =
// 427778066313557225181231220812180094976
TEST(TestRound, TestTrueNoAddKToResult)
{
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> in_x;
    libsnark::pb_variable<FieldT> in_k;

    FieldT in_C = FieldT("216319");
    in_x.allocate(pb, "x");
    in_k.allocate(pb, "k");
    pb.val(in_x) = FieldT("15212");
    pb.val(in_k) = FieldT("98645");

    MiMCe7_round_gadget<FieldT> round_gadget(
        pb, in_x, in_k, in_C, false, "round_gadget");
    round_gadget.generate_r1cs_witness();
    round_gadget.generate_r1cs_constraints();

    FieldT expected_out = FieldT("427778066313557225181231220812180094976");
    ASSERT_TRUE(expected_out == pb.val(round_gadget.result()));
}

// Testing that (15212  + 98645 + 216319)**7 + 98645 =
// 427778066313557225181231220812180193621
TEST(TestRound, TestTrueAddKToResult)
{
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> in_x;
    libsnark::pb_variable<FieldT> in_k;

    FieldT in_C = FieldT("216319");
    in_x.allocate(pb, "x");
    in_k.allocate(pb, "k");
    pb.val(in_x) = FieldT("15212");
    pb.val(in_k) = FieldT("98645");

    MiMCe7_round_gadget<FieldT> round_gadget(
        pb, in_x, in_k, in_C, true, "round_gadget");
    round_gadget.generate_r1cs_witness();
    round_gadget.generate_r1cs_constraints();

    FieldT expected_out = FieldT("427778066313557225181231220812180193621");
    ASSERT_TRUE(expected_out == pb.val(round_gadget.result()));
}

TEST(TestRound, TestFalseNoAddKToResult)
{
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> in_x;
    libsnark::pb_variable<FieldT> in_k;

    FieldT in_C = FieldT("216319");
    in_x.allocate(pb, "x");
    in_k.allocate(pb, "k");
    pb.val(in_x) = FieldT("15212");
    pb.val(in_k) = FieldT("98645");

    MiMCe7_round_gadget<FieldT> round_gadget(
        pb, in_x, in_k, in_C, false, "round_gadget");
    round_gadget.generate_r1cs_witness();
    round_gadget.generate_r1cs_constraints();

    FieldT expected_out = FieldT("4277780663135572251");
    ASSERT_FALSE(expected_out == pb.val(round_gadget.result()));
}

TEST(TestRound, TestFalseAddKToResult)
{
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> in_x;
    libsnark::pb_variable<FieldT> in_k;

    FieldT in_C = FieldT("216319");
    in_x.allocate(pb, "x");
    in_k.allocate(pb, "k");
    pb.val(in_x) = FieldT("15212");
    pb.val(in_k) = FieldT("98645");

    MiMCe7_round_gadget<FieldT> round_gadget(
        pb, in_x, in_k, in_C, true, "round_gadget");
    round_gadget.generate_r1cs_witness();
    round_gadget.generate_r1cs_constraints();

    FieldT expected_out = FieldT("42777806631355722518123");
    ASSERT_FALSE(expected_out == pb.val(round_gadget.result()));
}

TEST(TestMiMCPerm, TestTrue)
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

TEST(TestMiMCPerm, TestFalse)
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

TEST(TestMiMCMp, TestTrue)
{
    libsnark::protoboard<FieldT> pb;

    // Public input
    libsnark::pb_variable<FieldT> y;
    y.allocate(pb, "y");
    pb.set_input_sizes(1);

    // y = sha3_256("mimc")
    pb.val(y) = FieldT("1568395149631190174933950911896067630329022481212975289"
                       "0706581988986633412003");

    // Private inputs
    libsnark::pb_variable<FieldT> x;
    x.allocate(pb, "x");
    pb.val(x) = FieldT("3703141493535563179657531719960160174296085208671919316"
                       "200479060314459804651");

    MiMC_mp_gadget<FieldT> mimc_mp_gadget(pb, x, y, "gadget");
    mimc_mp_gadget.generate_r1cs_witness();
    mimc_mp_gadget.generate_r1cs_constraints();

    FieldT expected_out = FieldT("167979224495559946840631042142333962005996937"
                                 "15764605878168345782964540311877");
    ASSERT_TRUE(expected_out == pb.val(mimc_mp_gadget.result()));
}

TEST(TestMiMCMp, TestFalse)
{
    libsnark::protoboard<FieldT> pb;

    // Public input
    libsnark::pb_variable<FieldT> y;
    y.allocate(pb, "y");
    pb.set_input_sizes(1);
    pb.val(y) = FieldT("8272473133185905403731511349671041314111289765433456653"
                       "2528783843265082629790");

    // Private inputs
    libsnark::pb_variable<FieldT> x;
    x.allocate(pb, "x");
    pb.val(x) = FieldT("3703141493535563179657531719960160174296085208671919316"
                       "200479060314459804651");

    MiMC_mp_gadget<FieldT> mimc_mp_gadget(pb, x, y, "gadget");
    mimc_mp_gadget.generate_r1cs_witness();
    mimc_mp_gadget.generate_r1cs_constraints();

    FieldT not_expected_out = FieldT("15683951496311901749339509118960676303290"
                                     "224812129752890706581988986633412003");
    ASSERT_FALSE(not_expected_out == pb.val(mimc_mp_gadget.result()));
}

} // namespace
