// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/circuits/binary_operation.hpp"
#include "libzeth/circuits/circuit_utils.hpp"
#include "libzeth/core/include_libff.hpp"
#include "libzeth/core/utils.hpp"

#include <gtest/gtest.h>

using namespace libzeth;

using ppT = libff::default_ec_pp;
using FieldT = libff::Fr<ppT>;

namespace
{

TEST(TestXOR, TestTrue)
{
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> zero;
    zero.allocate(pb, "zero");
    pb.val(zero) = FieldT::zero();

    libsnark::pb_variable_array<FieldT> a = variable_array_from_bit_vector(
        {
            0, 0, 0, 0, 1, 1, 1, 1, // 0F // NOLINT
            0, 1, 0, 1, 0, 1, 0, 1, // 55 // NOLINT
            1, 0, 1, 0, 1, 0, 1, 0, // AA // NOLINT
            1, 1, 1, 1, 0, 0, 0, 0  // F0 // NOLINT
        },
        zero);

    libsnark::pb_variable_array<FieldT> b = variable_array_from_bit_vector(
        {
            1, 1, 1, 1, 0, 0, 0, 0, // F0 // NOLINT
            1, 0, 1, 0, 1, 0, 1, 0, // AA // NOLINT
            1, 0, 1, 0, 1, 0, 1, 0, // AA // NOLINT
            1, 1, 1, 1, 0, 0, 0, 0  // F0 // NOLINT
        },
        zero);

    libsnark::pb_variable_array<FieldT> xored;
    xored.allocate(pb, 32, "xored");

    xor_gadget<FieldT> xor_gadget(pb, a, b, xored);
    xor_gadget.generate_r1cs_constraints();
    xor_gadget.generate_r1cs_witness();

    libsnark::pb_variable_array<FieldT> expected =
        variable_array_from_bit_vector(
            {
                1, 1, 1, 1, 1, 1, 1, 1, // FF // NOLINT
                1, 1, 1, 1, 1, 1, 1, 1, // FF // NOLINT
                0, 0, 0, 0, 0, 0, 0, 0, // 00 // NOLINT
                0, 0, 0, 0, 0, 0, 0, 0  // 00 // NOLINT
            },
            zero);

    ASSERT_EQ(expected.get_bits(pb), xored.get_bits(pb));
}

TEST(TestXORConstant, TestTrue)
{
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> zero;
    zero.allocate(pb, "zero");
    pb.val(zero) = FieldT::zero();

    libsnark::pb_variable_array<FieldT> a = variable_array_from_bit_vector(
        {
            0, 0, 0, 0, 1, 1, 1, 1, // 0F // NOLINT
            0, 1, 0, 1, 0, 1, 0, 1, // 55 // NOLINT
            1, 0, 1, 0, 1, 0, 1, 0, // AA // NOLINT
            1, 1, 1, 1, 0, 0, 0, 0  // F0 // NOLINT
        },
        zero);

    libsnark::pb_variable_array<FieldT> b = variable_array_from_bit_vector(
        {
            1, 1, 1, 1, 0, 0, 0, 0, // F0 // NOLINT
            1, 0, 1, 0, 1, 0, 1, 0, // AA // NOLINT
            1, 0, 1, 0, 1, 0, 1, 0, // AA // NOLINT
            1, 1, 1, 1, 0, 0, 0, 0  // F0 // NOLINT
        },
        zero);

    std::vector<FieldT> c = {
        0, 0, 0, 0, 1, 1, 1, 1, // 0F // NOLINT
        1, 1, 1, 1, 0, 0, 0, 0, // F0 // NOLINT
        0, 0, 0, 0, 0, 0, 0, 0, // 00 // NOLINT
        1, 0, 1, 0, 1, 0, 1, 0  // AA // NOLINT
    };

    libsnark::pb_variable_array<FieldT> xored;
    xored.allocate(pb, 32, "xored");

    xor_constant_gadget<FieldT> xor_c_gadget(pb, a, b, c, xored);
    xor_c_gadget.generate_r1cs_constraints();
    xor_c_gadget.generate_r1cs_witness();

    libsnark::pb_variable_array<FieldT> expected =
        variable_array_from_bit_vector(
            {
                1, 1, 1, 1, 0, 0, 0, 0, // F0 // NOLINT
                0, 0, 0, 0, 1, 1, 1, 1, // 0F // NOLINT
                0, 0, 0, 0, 0, 0, 0, 0, // 00 // NOLINT
                1, 0, 1, 0, 1, 0, 1, 0  // AA // NOLINT
            },
            zero);

    ASSERT_EQ(expected.get_bits(pb), xored.get_bits(pb));
}

TEST(Testxor_rot, TestTrue)
{
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> zero;
    zero.allocate(pb, "zero");
    pb.val(zero) = FieldT::zero();

    libsnark::pb_variable_array<FieldT> a = variable_array_from_bit_vector(
        {
            0, 0, 0, 0, 1, 1, 1, 1, // 0F // NOLINT
            0, 1, 0, 1, 0, 1, 0, 1, // 55 // NOLINT
            1, 0, 1, 0, 1, 0, 1, 0, // AA // NOLINT
            1, 1, 1, 1, 0, 0, 0, 0  // F0 // NOLINT
        },
        zero);

    libsnark::pb_variable_array<FieldT> b = variable_array_from_bit_vector(
        {
            1, 1, 1, 1, 0, 0, 0, 0, // F0 // NOLINT
            1, 0, 1, 0, 1, 0, 1, 0, // AA // NOLINT
            1, 0, 1, 0, 1, 0, 1, 0, // AA // NOLINT
            1, 1, 1, 1, 0, 0, 0, 0  // F0 // NOLINT
        },
        zero);

    libsnark::pb_variable_array<FieldT> rot0;
    rot0.allocate(pb, 32, "rot0");

    libsnark::pb_variable_array<FieldT> rot8;
    rot8.allocate(pb, 32, "rot8");

    libsnark::pb_variable_array<FieldT> rot16;
    rot16.allocate(pb, 32, "rot16");

    libsnark::pb_variable_array<FieldT> rot24;
    rot24.allocate(pb, 32, "rot24");

    libsnark::pb_variable_array<FieldT> rot32;
    rot32.allocate(pb, 32, "rot32");

    xor_rot_gadget<FieldT> xor_rot0_gadget(pb, a, b, size_t(0), rot0);
    xor_rot0_gadget.generate_r1cs_constraints();
    xor_rot0_gadget.generate_r1cs_witness();

    xor_rot_gadget<FieldT> xor_rot8_gadget(pb, a, b, size_t(8), rot8);
    xor_rot8_gadget.generate_r1cs_constraints();
    xor_rot8_gadget.generate_r1cs_witness();

    xor_rot_gadget<FieldT> xor_rot16_gadget(pb, a, b, size_t(16), rot16);
    xor_rot16_gadget.generate_r1cs_constraints();
    xor_rot16_gadget.generate_r1cs_witness();

    xor_rot_gadget<FieldT> xor_rot24_gadget(pb, a, b, size_t(24), rot24);
    xor_rot24_gadget.generate_r1cs_constraints();
    xor_rot24_gadget.generate_r1cs_witness();

    xor_rot_gadget<FieldT> xor_rot32_gadget(pb, a, b, size_t(32), rot32);
    xor_rot32_gadget.generate_r1cs_constraints();
    xor_rot32_gadget.generate_r1cs_witness();

    libsnark::pb_variable_array<FieldT> expected0 =
        variable_array_from_bit_vector(
            {
                1, 1, 1, 1, 1, 1, 1, 1, // FF // NOLINT
                1, 1, 1, 1, 1, 1, 1, 1, // FF // NOLINT
                0, 0, 0, 0, 0, 0, 0, 0, // 00 // NOLINT
                0, 0, 0, 0, 0, 0, 0, 0  // 00 // NOLINT
            },
            zero);

    libsnark::pb_variable_array<FieldT> expected8 =
        variable_array_from_bit_vector(
            {
                0, 0, 0, 0, 0, 0, 0, 0, // 00 // NOLINT
                1, 1, 1, 1, 1, 1, 1, 1, // FF // NOLINT
                1, 1, 1, 1, 1, 1, 1, 1, // FF // NOLINT
                0, 0, 0, 0, 0, 0, 0, 0  // 00 // NOLINT
            },
            zero);

    libsnark::pb_variable_array<FieldT> expected16 =
        variable_array_from_bit_vector(
            {
                0, 0, 0, 0, 0, 0, 0, 0, // 00 // NOLINT
                0, 0, 0, 0, 0, 0, 0, 0, // 00 // NOLINT
                1, 1, 1, 1, 1, 1, 1, 1, // FF // NOLINT
                1, 1, 1, 1, 1, 1, 1, 1  // FF // NOLINT
            },
            zero);

    libsnark::pb_variable_array<FieldT> expected24 =
        variable_array_from_bit_vector(
            {
                1, 1, 1, 1, 1, 1, 1, 1, // FF // NOLINT
                0, 0, 0, 0, 0, 0, 0, 0, // 00 // NOLINT
                0, 0, 0, 0, 0, 0, 0, 0, // 00 // NOLINT
                1, 1, 1, 1, 1, 1, 1, 1  // FF // NOLINT
            },
            zero);

    ASSERT_EQ(expected0.get_bits(pb), rot0.get_bits(pb));
    ASSERT_EQ(expected8.get_bits(pb), rot8.get_bits(pb));
    ASSERT_EQ(expected16.get_bits(pb), rot16.get_bits(pb));
    ASSERT_EQ(expected24.get_bits(pb), rot24.get_bits(pb));
    ASSERT_EQ(expected0.get_bits(pb), rot32.get_bits(pb));
}

TEST(Testdouble_packed, TestTrue)
{
    libsnark::protoboard<FieldT> pb;
    libsnark::pb_variable<FieldT> zero;
    zero.allocate(pb, "zero");
    pb.val(zero) = FieldT::zero();

    libsnark::pb_variable_array<FieldT> a = variable_array_from_bit_vector(
        {
            1, 0, 0, 0, 1, 1, 1, 1, // 8F // NOLINT
            0, 1, 0, 1, 0, 1, 0, 1, // 55 // NOLINT
            1, 0, 1, 0, 1, 0, 1, 0, // AA // NOLINT
            1, 1, 1, 1, 0, 0, 0, 0  // F0 // NOLINT
        },
        zero);

    libsnark::pb_variable_array<FieldT> b = variable_array_from_bit_vector(
        {
            1, 1, 1, 1, 0, 0, 0, 0, // F0 // NOLINT
            1, 0, 1, 0, 1, 0, 1, 0, // AA // NOLINT
            1, 0, 1, 0, 1, 0, 1, 0, // AA // NOLINT
            1, 1, 1, 1, 0, 0, 0, 0  // F0 // NOLINT
        },
        zero);

    libsnark::pb_variable_array<FieldT> add;
    add.allocate(pb, 32, "add");

    double_bit32_sum_eq_gadget<FieldT> add_mod32_gadget(pb, a, b, add);
    add_mod32_gadget.generate_r1cs_constraints();
    add_mod32_gadget.generate_r1cs_witness();

    libsnark::pb_variable_array<FieldT> expected =
        variable_array_from_bit_vector(
            {
                1, 0, 0, 0, 0, 0, 0, 0, // 80 // NOLINT
                0, 0, 0, 0, 0, 0, 0, 0, // 00 // NOLINT
                0, 1, 0, 1, 0, 1, 0, 1, // 55 // NOLINT
                1, 1, 1, 0, 0, 0, 0, 0  // E0 // NOLINT
            },
            zero);

    ASSERT_EQ(expected.get_bits(pb), add.get_bits(pb));
}

} // namespace

int main(int argc, char **argv)
{
    // /!\ WARNING: Do once for all tests. Do not
    // forget to do this !!!!
    ppT::init_public_params();

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
