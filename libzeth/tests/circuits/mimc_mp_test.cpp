// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/circuits/mimc/mimc_mp.hpp"

#include <gtest/gtest.h>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/curves/bls12_377/bls12_377_pp.hpp>

using namespace libzeth;

template<typename FieldT>
using MiMCe7_round_gadget = MiMC_round_gadget<FieldT, 7>;
template<typename FieldT>
using MiMCe7_permutation_gadget = MiMC_permutation_gadget<FieldT, 7, 91>;
template<typename FieldT>
using MiMCe17_round_gadget = MiMC_round_gadget<FieldT, 17>;
template<typename FieldT>
using MiMCe17_ALT_BN128_permutation_gadget =
    MiMC_permutation_gadget<FieldT, 17, 65>;
template<typename FieldT>
using MiMCe17_BLS12_377_permutation_gadget =
    MiMC_permutation_gadget<FieldT, 17, 62>;

// Test data here specialized for alt_bn128
using pp = libff::alt_bn128_pp;
using Field = libff::Fr<pp>;

namespace
{

// Testing that (15212  + 98645 + 216319)**7 =
// 427778066313557225181231220812180094976
TEST(TestMiMC, MiMC7Round)
{
    libsnark::protoboard<Field> pb;
    libsnark::pb_variable<Field> in_x;
    libsnark::pb_variable<Field> in_k;
    libsnark::pb_variable<Field> result;

    Field in_C = Field("216319");
    in_x.allocate(pb, "x");
    in_k.allocate(pb, "k");
    pb.val(in_x) = Field("15212");
    pb.val(in_k) = Field("98645");

    result.allocate(pb, "result");
    MiMCe7_round_gadget<Field> round_gadget(
        pb, in_x, in_k, in_C, result, "round_gadget");
    round_gadget.generate_r1cs_constraints();
    round_gadget.generate_r1cs_witness();

    Field expected_out = Field("427778066313557225181231220812180094976");
    ASSERT_TRUE(pb.is_satisfied());
    ASSERT_TRUE(expected_out == pb.val(result));
}

TEST(TestMiMC, MiMC7RoundIncorrect)
{
    libsnark::protoboard<Field> pb;
    libsnark::pb_variable<Field> in_x;
    libsnark::pb_variable<Field> in_k;
    libsnark::pb_variable<Field> result;

    Field in_C = Field("12345");
    in_x.allocate(pb, "x");
    in_k.allocate(pb, "k");
    pb.val(in_x) = Field("67890");
    pb.val(in_k) = Field("98645");

    result.allocate(pb, "result");
    MiMCe7_round_gadget<Field> round_gadget(
        pb, in_x, in_k, in_C, result, "round_gadget");
    round_gadget.generate_r1cs_constraints();
    round_gadget.generate_r1cs_witness();

    Field unexpected_out = Field("427778066313557225181231220812180094976");
    ASSERT_TRUE(pb.is_satisfied());
    ASSERT_FALSE(unexpected_out == pb.val(result));
}

// Testing that (15212  + 98645 + 216319)**7 + 98645 =
// 427778066313557225181231220812180193621
TEST(TestMiMC, MiMC7RoundAddToResult)
{
    libsnark::protoboard<Field> pb;
    libsnark::pb_variable<Field> in_x;
    libsnark::pb_variable<Field> in_k;
    libsnark::pb_variable<Field> result;

    Field in_C = Field("216319");
    in_x.allocate(pb, "x");
    in_k.allocate(pb, "k");
    pb.val(in_x) = Field("15212");
    pb.val(in_k) = Field("98645");

    result.allocate(pb, "result");
    MiMCe7_round_gadget<Field> round_gadget(
        pb, in_x, in_k, in_C, result, in_k, "round_gadget");
    round_gadget.generate_r1cs_constraints();
    round_gadget.generate_r1cs_witness();

    Field expected_out = Field("427778066313557225181231220812180193621");
    ASSERT_TRUE(pb.is_satisfied());
    ASSERT_TRUE(expected_out == pb.val(result));
}

TEST(TestMiMC, MiMC7RoundAddToResultIncorrect)
{
    libsnark::protoboard<Field> pb;
    libsnark::pb_variable<Field> in_x;
    libsnark::pb_variable<Field> in_k;
    libsnark::pb_variable<Field> result;

    Field in_C = Field("12345");
    in_x.allocate(pb, "x");
    in_k.allocate(pb, "k");
    pb.val(in_x) = Field("67890");
    pb.val(in_k) = Field("98645");

    result.allocate(pb, "result");
    MiMCe7_round_gadget<Field> round_gadget(
        pb, in_x, in_k, in_C, result, in_k, "round_gadget");
    round_gadget.generate_r1cs_constraints();
    round_gadget.generate_r1cs_witness();

    Field unexpected_out = Field("427778066313557225181231220812180193621");
    ASSERT_TRUE(pb.is_satisfied());
    ASSERT_FALSE(unexpected_out == pb.val(result));
}

TEST(TestMiMC, MiMC7Perm)
{
    libsnark::protoboard<Field> pb;

    libsnark::pb_variable<Field> in_x;
    libsnark::pb_variable<Field> in_k;
    libsnark::pb_variable<Field> result;
    in_x.allocate(pb, "x");
    in_k.allocate(pb, "k");
    result.allocate(pb, "result");

    pb.val(in_x) = Field("3703141493535563179657531719960160174296085208671919"
                         "316200479060314459804651");
    pb.val(in_k) = Field("1568395149631190174933950911896067630329022481212975"
                         "2890706581988986633412003");

    MiMC_permutation_gadget<Field, 7, 91> mimc_gadget(
        pb, in_x, in_k, result, "mimc_gadget");
    mimc_gadget.generate_r1cs_constraints();
    mimc_gadget.generate_r1cs_witness();

    Field expected_out = Field("192990723315478049773124691205698348115617480"
                               "95378968014959488920239255590840");
    ASSERT_TRUE(pb.is_satisfied());
    ASSERT_TRUE(expected_out == pb.val(result));
}

TEST(TestMiMC, MiMC7PermIncorrect)
{
    libsnark::protoboard<Field> pb;

    libsnark::pb_variable<Field> in_x;
    libsnark::pb_variable<Field> in_k;
    libsnark::pb_variable<Field> result;
    in_x.allocate(pb, "x");
    in_k.allocate(pb, "k");
    result.allocate(pb, "result");

    pb.val(in_x) = Field("3703141493535563179657531719960160174296085208671919"
                         "316200479060314459804651");
    pb.val(in_k) = Field("13455131405143248756924738814405142");

    MiMCe7_permutation_gadget<Field> mimc_gadget(
        pb, in_x, in_k, result, "mimc_gadget");
    mimc_gadget.generate_r1cs_constraints();
    mimc_gadget.generate_r1cs_witness();

    Field unexpected_out = Field("1929907233154780497731246912056983481156174"
                                 "8095378968014959488920239255590840");
    ASSERT_TRUE(pb.is_satisfied());
    ASSERT_FALSE(unexpected_out == pb.val(result));
}

TEST(TestMiMC, MiMC7Mp)
{
    libsnark::protoboard<Field> pb;

    // Public input
    libsnark::pb_variable<Field> y;
    y.allocate(pb, "y");
    pb.set_input_sizes(1);

    // y = sha3_256("mimc")
    pb.val(y) = Field("1568395149631190174933950911896067630329022481212975289"
                      "0706581988986633412003");

    // Private inputs
    libsnark::pb_variable<Field> x;
    x.allocate(pb, "x");
    pb.val(x) = Field("3703141493535563179657531719960160174296085208671919316"
                      "200479060314459804651");

    libsnark::pb_variable<Field> result;
    result.allocate(pb, "result");

    MiMC_mp_gadget<Field, MiMCe7_permutation_gadget<Field>> mimc_mp_gadget(
        pb, x, y, result, "gadget");
    mimc_mp_gadget.generate_r1cs_constraints();
    mimc_mp_gadget.generate_r1cs_witness();

    Field expected_out = Field("167979224495559946840631042142333962005996937"
                               "15764605878168345782964540311877");
    ASSERT_TRUE(pb.is_satisfied());
    ASSERT_TRUE(expected_out == pb.val(result));
}

TEST(TestMiMC, MiMC7MpIncorrect)
{
    libsnark::protoboard<Field> pb;

    // Public input
    libsnark::pb_variable<Field> y;
    y.allocate(pb, "y");
    pb.set_input_sizes(1);
    pb.val(y) = Field("8272473133185905403731511349671041314111289765433456653"
                      "2528783843265082629790");

    // Private inputs
    libsnark::pb_variable<Field> x;
    x.allocate(pb, "x");
    pb.val(x) = Field("3703141493535563179657531719960160174296085208671919316"
                      "200479060314459804651");

    libsnark::pb_variable<Field> result;
    result.allocate(pb, "result");

    MiMC_mp_gadget<Field, MiMCe7_permutation_gadget<Field>> mimc_mp_gadget(
        pb, x, y, result, "gadget");
    mimc_mp_gadget.generate_r1cs_constraints();
    mimc_mp_gadget.generate_r1cs_witness();

    Field unexpected_out = Field("1679792244955599468406310421423339620059969"
                                 "3715764605878168345782964540311877");
    ASSERT_TRUE(pb.is_satisfied());
    ASSERT_FALSE(unexpected_out == pb.val(result));
}

// Testing that (15212  + 98645 + 216319)**7 =
// 427778066313557225181231220812180094976
TEST(TestMiMC, MiMC17_ALT_BN128_Round)
{
    using Field = libff::alt_bn128_Fr;

    libsnark::protoboard<Field> pb;
    libsnark::pb_variable<Field> in_x;
    libsnark::pb_variable<Field> in_k;
    libsnark::pb_variable<Field> result;

    in_x.allocate(pb, "x");
    in_k.allocate(pb, "k");
    result.allocate(pb, "result");

    // Test data from client test (test_mimc_alt_bn128_round), to ensure
    // consistency between implementations.

    pb.val(in_x) = Field("340282366920938463463374607431768211456");
    pb.val(in_k) = Field("28948022309329048855892746252171976963317496166410141"
                         "009864396001978282409983");
    Field in_C = Field("1422006791884799603110814443576367281105075806594536430"
                       "8986253046354060608451");

    MiMCe17_round_gadget<Field> round_gadget(
        pb, in_x, in_k, in_C, result, "round_gadget");
    round_gadget.generate_r1cs_constraints();
    round_gadget.generate_r1cs_witness();

    Field expected_out = Field("15194574649778181158537940501307832704788048781"
                               "286507777438072456493095881604");
    ASSERT_TRUE(pb.is_satisfied());
    ASSERT_TRUE(expected_out == pb.val(result));
}

TEST(TestMiMC, MiMC17_ALT_BN128_MP)
{
    using Field = libff::alt_bn128_Fr;

    // Test data from client test (test_mimc_alt_bn128_hash), to ensure
    // consistency between implementations.

    const Field m_val("340282366920938463463374607431768211456");
    const Field k_val("28948022309329048855892746252171976963317496166410141009"
                      "864396001978282409983");
    const Field h_val("14599678357063082723814206975733222579132256174923645170"
                      "354481857040188426666");

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

    libsnark::pb_variable<Field> h;
    h.allocate(pb, "h");

    MiMC_mp_gadget<Field, MiMCe17_ALT_BN128_permutation_gadget<Field>>
        mimc_mp_gadget(pb, m, k, h, "mimc_mp");
    mimc_mp_gadget.generate_r1cs_constraints();
    mimc_mp_gadget.generate_r1cs_witness();

    // Check that the circuit is satisfied, and that the expected result is
    // generated.
    ASSERT_TRUE(pb.is_satisfied());
    ASSERT_EQ(h_val, pb.val(h));
}

// Testing that (15212  + 98645 + 216319)**7 =
// 427778066313557225181231220812180094976
TEST(TestMiMC, MiMC17_BLS12_377_Round)
{
    using Field = libff::bls12_377_Fr;

    libsnark::protoboard<Field> pb;
    libsnark::pb_variable<Field> in_x;
    libsnark::pb_variable<Field> in_k;
    libsnark::pb_variable<Field> result;

    in_x.allocate(pb, "x");
    in_k.allocate(pb, "k");
    result.allocate(pb, "result");

    // Test data from client test (test_mimc_bls12_377_round), to ensure
    // consistency between implementations.

    pb.val(in_x) = Field("340282366920938463463374607431768211456");
    pb.val(in_k) = Field("36146370610439375831462714358273373691897981609479495"
                         "26058695634226054692860");
    Field in_C = Field("5775606169419625606859319496982126279674858730791300481"
                       "051019590436651369410");

    MiMCe17_round_gadget<Field> round_gadget(
        pb, in_x, in_k, in_C, result, "round_gadget");
    round_gadget.generate_r1cs_constraints();
    round_gadget.generate_r1cs_witness();

    Field expected_out = Field("70652923384013840748711649474482841764205668417"
                               "1152884149736992660816802274");
    ASSERT_TRUE(pb.is_satisfied());
    ASSERT_EQ(expected_out, pb.val(result));
}

TEST(TestMiMC, MiMC17_BLS12_377_MP)
{
    using Field = libff::bls12_377_Fr;

    // Test data from client test (test_mimc_bls12_377_hash), to ensure
    // consistency between implementations.

    const Field m_val(
        "361463706104393758314627143582733736918979816094794952605869"
        "5634226054692860");
    const Field k_val(
        "577560616941962560685931949698212627967485873079130048105101"
        "9590436651369410");
    const Field h_val(
        "580310635483157120553405751259383795319189070903739068091192"
        "5249983717812220");

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

    libsnark::pb_variable<Field> h;
    h.allocate(pb, "h");

    MiMC_mp_gadget<Field, MiMCe17_BLS12_377_permutation_gadget<Field>>
        mimc_mp_gadget(pb, m, k, h, "mimc_mp");
    mimc_mp_gadget.generate_r1cs_constraints();
    mimc_mp_gadget.generate_r1cs_witness();

    // Check that the circuit is satisfied, and that the expected result is
    // generated.
    ASSERT_TRUE(pb.is_satisfied());
    ASSERT_EQ(h_val, pb.val(h));
}

} // namespace

int main(int argc, char **argv)
{
    // /!\ WARNING: Do once for all tests. Do not
    // forget to do this !!!!
    pp::init_public_params();
    libff::bls12_377_pp::init_public_params();

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
