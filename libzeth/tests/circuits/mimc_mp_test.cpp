// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/circuits/mimc/mimc_mp.hpp"

#include <gtest/gtest.h>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/curves/bls12_377/bls12_377_pp.hpp>

using namespace libzeth;

// Test data here specialized for alt_bn128
using ppT = libff::alt_bn128_pp;
using FieldT = libff::Fr<ppT>;

namespace
{

// Testing that (15212  + 98645 + 216319)**7 =
// 427778066313557225181231220812180094976
TEST(TestMiMC, MiMC7RoundTrueNoAddKToResult)
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
    ASSERT_TRUE(pb.is_satisfied());
    ASSERT_TRUE(expected_out == pb.val(round_gadget.result()));
}

TEST(TestMiMC, MiMC7RoundFalseNoAddKToResult)
{
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> in_x;
    libsnark::pb_variable<FieldT> in_k;

    FieldT in_C = FieldT("12345");
    in_x.allocate(pb, "x");
    in_k.allocate(pb, "k");
    pb.val(in_x) = FieldT("67890");
    pb.val(in_k) = FieldT("98645");

    MiMCe7_round_gadget<FieldT> round_gadget(
        pb, in_x, in_k, in_C, false, "round_gadget");
    round_gadget.generate_r1cs_witness();
    round_gadget.generate_r1cs_constraints();

    // The expected result is 5860470760135874487852644433920000000
    FieldT unexpected_out = FieldT("427778066313557225181231220812180094976");
    ASSERT_TRUE(pb.is_satisfied());
    ASSERT_FALSE(unexpected_out == pb.val(round_gadget.result()));
}

// Testing that (15212  + 98645 + 216319)**7 + 98645 =
// 427778066313557225181231220812180193621
TEST(TestMiMC, MiMC7RoundTrueAddKToResult)
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
    ASSERT_TRUE(pb.is_satisfied());
    ASSERT_TRUE(expected_out == pb.val(round_gadget.result()));
}

TEST(TestMiMC, MiMC7RoundFalseAddKToResult)
{
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> in_x;
    libsnark::pb_variable<FieldT> in_k;

    FieldT in_C = FieldT("12345");
    in_x.allocate(pb, "x");
    in_k.allocate(pb, "k");
    pb.val(in_x) = FieldT("67890");
    pb.val(in_k) = FieldT("98645");

    MiMCe7_round_gadget<FieldT> round_gadget(
        pb, in_x, in_k, in_C, true, "round_gadget");
    round_gadget.generate_r1cs_witness();
    round_gadget.generate_r1cs_constraints();

    // The expected result is 5860470760135874487852644433920098645
    FieldT unexpected_out = FieldT("427778066313557225181231220812180193621");
    ASSERT_TRUE(pb.is_satisfied());
    ASSERT_FALSE(unexpected_out == pb.val(round_gadget.result()));
}

TEST(TestMiMC, MiMC7PermTrue)
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
    ASSERT_TRUE(pb.is_satisfied());
    ASSERT_TRUE(expected_out == pb.val(mimc_gadget.result()));
}

TEST(TestMiMC, MiMC7PermFalse)
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

    // The expected result is
    // 20244553093364853409529130494302294324388714964661285862293421948544829732374
    FieldT unexpected_out =
        FieldT("192990723315478049773124691205698348115617480"
               "95378968014959488920239255590840");
    ASSERT_TRUE(pb.is_satisfied());
    ASSERT_FALSE(unexpected_out == pb.val(mimc_gadget.result()));
}

TEST(TestMiMC, MiMC7MpTrue)
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

    MiMC_mp_gadget<FieldT, MiMCe7_permutation_gadget<FieldT>> mimc_mp_gadget(
        pb, x, y, "gadget");
    mimc_mp_gadget.generate_r1cs_witness();
    mimc_mp_gadget.generate_r1cs_constraints();

    FieldT expected_out = FieldT("167979224495559946840631042142333962005996937"
                                 "15764605878168345782964540311877");
    ASSERT_TRUE(pb.is_satisfied());
    ASSERT_TRUE(expected_out == pb.val(mimc_mp_gadget.result()));
}

TEST(TestMiMC, MiMC7MpFalse)
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

    MiMC_mp_gadget<FieldT, MiMCe7_permutation_gadget<FieldT>> mimc_mp_gadget(
        pb, x, y, "gadget");
    mimc_mp_gadget.generate_r1cs_witness();
    mimc_mp_gadget.generate_r1cs_constraints();

    // The expected result is
    // 5112273298838179316278619287286725360759332011395674677782848093455126184244
    FieldT unexpected_out =
        FieldT("167979224495559946840631042142333962005996937"
               "15764605878168345782964540311877");
    ASSERT_TRUE(pb.is_satisfied());
    ASSERT_FALSE(unexpected_out == pb.val(mimc_mp_gadget.result()));
}

TEST(TestMiMC, TestMiMC31)
{
    using Field = libff::bls12_377_Fr;

    // Test data from client test
    const Field m_val(
        "361463706104393758314627143582733736918979816094794952605869"
        "5634226054692860");
    const Field k_val(
        "577560616941962560685931949698212627967485873079130048105101"
        "9590436651369410");
    const Field h_val(
        "757520454940410747883073955769867933053765668805066446289274"
        "1835534561279075");

    libsnark::protoboard<Field> pb;

    // Public input
    libsnark::pb_variable<Field> k;
    k.allocate(pb, "k");
    pb.set_input_sizes(1);
    pb.val(k) = k_val;

    // Private inputs
    libsnark::pb_variable<Field> m;
    m.allocate(pb, "m");
    pb.val(m) = m_val;

    MiMC_mp_gadget<Field, MiMCe31_permutation_gadget<Field>> mimc_mp_gadget(
        pb, m, k, "mimc_mp");
    mimc_mp_gadget.generate_r1cs_witness();
    mimc_mp_gadget.generate_r1cs_constraints();

    // Check that the circuit is satisfied, and that the expected result is
    // generated.
    ASSERT_TRUE(pb.is_satisfied());
    ASSERT_EQ(h_val, pb.val(mimc_mp_gadget.result()));
}

} // namespace

int main(int argc, char **argv)
{
    // /!\ WARNING: Do once for all tests. Do not
    // forget to do this !!!!
    ppT::init_public_params();
    libff::bls12_377_pp::init_public_params();

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
