// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/circuits/binary_operation.hpp"
#include "libzeth/circuits/circuit_utils.hpp"
#include "libzeth/core/include_libff.hpp"
#include "libzeth/core/utils.hpp"
#include "zeth_config.h"

#include <gtest/gtest.h>

using namespace libzeth;

using pp = defaults::pp;
using Field = defaults::Field;

namespace
{

TEST(TestXOR, TestTrue)
{
    libsnark::protoboard<Field> pb;

    libsnark::pb_variable_array<Field> a = variable_array_from_bit_vector(
        pb,
        {
            0, 0, 0, 0, 1, 1, 1, 1, // 0F
            0, 1, 0, 1, 0, 1, 0, 1, // 55
            1, 0, 1, 0, 1, 0, 1, 0, // AA
            1, 1, 1, 1, 0, 0, 0, 0  // F0
        },
        "a");

    libsnark::pb_variable_array<Field> b = variable_array_from_bit_vector(
        pb,
        {
            1, 1, 1, 1, 0, 0, 0, 0, // F0
            1, 0, 1, 0, 1, 0, 1, 0, // AA
            1, 0, 1, 0, 1, 0, 1, 0, // AA
            1, 1, 1, 1, 0, 0, 0, 0  // F0
        },
        "b");

    libsnark::pb_variable_array<Field> xored;
    xored.allocate(pb, 32, "xored");

    xor_gadget<Field> xor_gadget(pb, a, b, xored);
    xor_gadget.generate_r1cs_constraints();
    xor_gadget.generate_r1cs_witness();

    libsnark::pb_variable_array<Field> expected =
        variable_array_from_bit_vector(
            pb,
            {
                1, 1, 1, 1, 1, 1, 1, 1, // FF
                1, 1, 1, 1, 1, 1, 1, 1, // FF
                0, 0, 0, 0, 0, 0, 0, 0, // 00
                0, 0, 0, 0, 0, 0, 0, 0  // 00
            },
            "expected");

    ASSERT_EQ(expected.get_bits(pb), xored.get_bits(pb));
}

TEST(TestXORConstant, TestTrue)
{
    libsnark::protoboard<Field> pb;

    libsnark::pb_variable_array<Field> a = variable_array_from_bit_vector(
        pb,
        {
            0, 0, 0, 0, 1, 1, 1, 1, // 0F
            0, 1, 0, 1, 0, 1, 0, 1, // 55
            1, 0, 1, 0, 1, 0, 1, 0, // AA
            1, 1, 1, 1, 0, 0, 0, 0  // F0
        },
        "a");

    libsnark::pb_variable_array<Field> b = variable_array_from_bit_vector(
        pb,
        {
            1, 1, 1, 1, 0, 0, 0, 0, // F0
            1, 0, 1, 0, 1, 0, 1, 0, // AA
            1, 0, 1, 0, 1, 0, 1, 0, // AA
            1, 1, 1, 1, 0, 0, 0, 0  // F0
        },
        "b");

    std::vector<Field> c = {
        0, 0, 0, 0, 1, 1, 1, 1, // 0F
        1, 1, 1, 1, 0, 0, 0, 0, // F0
        0, 0, 0, 0, 0, 0, 0, 0, // 00
        1, 0, 1, 0, 1, 0, 1, 0  // AA
    };

    libsnark::pb_variable_array<Field> xored;
    xored.allocate(pb, 32, "xored");

    xor_constant_gadget<Field> xor_c_gadget(pb, a, b, c, xored);
    xor_c_gadget.generate_r1cs_constraints();
    xor_c_gadget.generate_r1cs_witness();

    libsnark::pb_variable_array<Field> expected =
        variable_array_from_bit_vector(
            pb,
            {
                1, 1, 1, 1, 0, 0, 0, 0, // F0
                0, 0, 0, 0, 1, 1, 1, 1, // 0F
                0, 0, 0, 0, 0, 0, 0, 0, // 00
                1, 0, 1, 0, 1, 0, 1, 0  // AA
            },
            "expected");

    ASSERT_EQ(expected.get_bits(pb), xored.get_bits(pb));
}

TEST(Testxor_rot, TestTrue)
{
    libsnark::protoboard<Field> pb;

    libsnark::pb_variable_array<Field> a = variable_array_from_bit_vector(
        pb,
        {
            0, 0, 0, 0, 1, 1, 1, 1, // 0F
            0, 1, 0, 1, 0, 1, 0, 1, // 55
            1, 0, 1, 0, 1, 0, 1, 0, // AA
            1, 1, 1, 1, 0, 0, 0, 0  // F0
        },
        "a");

    libsnark::pb_variable_array<Field> b = variable_array_from_bit_vector(
        pb,
        {
            1, 1, 1, 1, 0, 0, 0, 0, // F0
            1, 0, 1, 0, 1, 0, 1, 0, // AA
            1, 0, 1, 0, 1, 0, 1, 0, // AA
            1, 1, 1, 1, 0, 0, 0, 0  // F0
        },
        "b");

    libsnark::pb_variable_array<Field> rot0;
    rot0.allocate(pb, 32, "rot0");

    libsnark::pb_variable_array<Field> rot8;
    rot8.allocate(pb, 32, "rot8");

    libsnark::pb_variable_array<Field> rot16;
    rot16.allocate(pb, 32, "rot16");

    libsnark::pb_variable_array<Field> rot24;
    rot24.allocate(pb, 32, "rot24");

    libsnark::pb_variable_array<Field> rot32;
    rot32.allocate(pb, 32, "rot32");

    xor_rot_gadget<Field> xor_rot0_gadget(pb, a, b, size_t(0), rot0);
    xor_rot0_gadget.generate_r1cs_constraints();
    xor_rot0_gadget.generate_r1cs_witness();

    xor_rot_gadget<Field> xor_rot8_gadget(pb, a, b, size_t(8), rot8);
    xor_rot8_gadget.generate_r1cs_constraints();
    xor_rot8_gadget.generate_r1cs_witness();

    xor_rot_gadget<Field> xor_rot16_gadget(pb, a, b, size_t(16), rot16);
    xor_rot16_gadget.generate_r1cs_constraints();
    xor_rot16_gadget.generate_r1cs_witness();

    xor_rot_gadget<Field> xor_rot24_gadget(pb, a, b, size_t(24), rot24);
    xor_rot24_gadget.generate_r1cs_constraints();
    xor_rot24_gadget.generate_r1cs_witness();

    xor_rot_gadget<Field> xor_rot32_gadget(pb, a, b, size_t(32), rot32);
    xor_rot32_gadget.generate_r1cs_constraints();
    xor_rot32_gadget.generate_r1cs_witness();

    libsnark::pb_variable_array<Field> expected0 =
        variable_array_from_bit_vector(
            pb,
            {
                1, 1, 1, 1, 1, 1, 1, 1, // FF
                1, 1, 1, 1, 1, 1, 1, 1, // FF
                0, 0, 0, 0, 0, 0, 0, 0, // 00
                0, 0, 0, 0, 0, 0, 0, 0  // 00
            },
            "expected0");

    libsnark::pb_variable_array<Field> expected8 =
        variable_array_from_bit_vector(
            pb,
            {
                0, 0, 0, 0, 0, 0, 0, 0, // 00
                1, 1, 1, 1, 1, 1, 1, 1, // FF
                1, 1, 1, 1, 1, 1, 1, 1, // FF
                0, 0, 0, 0, 0, 0, 0, 0  // 00
            },
            "expected8");

    libsnark::pb_variable_array<Field> expected16 =
        variable_array_from_bit_vector(
            pb,
            {
                0, 0, 0, 0, 0, 0, 0, 0, // 00
                0, 0, 0, 0, 0, 0, 0, 0, // 00
                1, 1, 1, 1, 1, 1, 1, 1, // FF
                1, 1, 1, 1, 1, 1, 1, 1  // FF
            },
            "expected16");

    libsnark::pb_variable_array<Field> expected24 =
        variable_array_from_bit_vector(
            pb,
            {
                1, 1, 1, 1, 1, 1, 1, 1, // FF
                0, 0, 0, 0, 0, 0, 0, 0, // 00
                0, 0, 0, 0, 0, 0, 0, 0, // 00
                1, 1, 1, 1, 1, 1, 1, 1  // FF
            },
            "expected24");

    ASSERT_EQ(expected0.get_bits(pb), rot0.get_bits(pb));
    ASSERT_EQ(expected8.get_bits(pb), rot8.get_bits(pb));
    ASSERT_EQ(expected16.get_bits(pb), rot16.get_bits(pb));
    ASSERT_EQ(expected24.get_bits(pb), rot24.get_bits(pb));
    ASSERT_EQ(expected0.get_bits(pb), rot32.get_bits(pb));
}

TEST(Testdouble_packed, TestTrue)
{
    libsnark::protoboard<Field> pb;

    libsnark::pb_variable_array<Field> a = variable_array_from_bit_vector(
        pb,
        {
            1, 0, 0, 0, 1, 1, 1, 1, // 8F
            0, 1, 0, 1, 0, 1, 0, 1, // 55
            1, 0, 1, 0, 1, 0, 1, 0, // AA
            1, 1, 1, 1, 0, 0, 0, 0  // F0
        },
        "a");

    libsnark::pb_variable_array<Field> b = variable_array_from_bit_vector(
        pb,
        {
            1, 1, 1, 1, 0, 0, 0, 0, // F0
            1, 0, 1, 0, 1, 0, 1, 0, // AA
            1, 0, 1, 0, 1, 0, 1, 0, // AA
            1, 1, 1, 1, 0, 0, 0, 0  // F0
        },
        "b");

    libsnark::pb_variable_array<Field> add;
    add.allocate(pb, 32, "add");

    double_bit32_sum_eq_gadget<Field> add_mod32_gadget(pb, a, b, add);
    add_mod32_gadget.generate_r1cs_constraints();
    add_mod32_gadget.generate_r1cs_witness();

    libsnark::pb_variable_array<Field> expected =
        variable_array_from_bit_vector(
            pb,
            {
                1, 0, 0, 0, 0, 0, 0, 0, // 80
                0, 0, 0, 0, 0, 0, 0, 0, // 00
                0, 1, 0, 1, 0, 1, 0, 1, // 55
                1, 1, 1, 0, 0, 0, 0, 0  // E0
            },
            "expected");

    ASSERT_EQ(expected.get_bits(pb), add.get_bits(pb));
}

} // namespace

int main(int argc, char **argv)
{
    // /!\ WARNING: Do once for all tests. Do not
    // forget to do this !!!!
    pp::init_public_params();

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
