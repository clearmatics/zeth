// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/circuits/blake2s/blake2s.hpp"
#include "libzeth/circuits/blake2s/g_primitive.hpp"
#include "libzeth/circuits/circuit_types.hpp"
#include "libzeth/circuits/circuit_utils.hpp"
#include "libzeth/core/utils.hpp"
#include "zeth_config.h"

#include <gtest/gtest.h>

using namespace libsnark;
using namespace libzeth;
using pp = defaults::pp;
using Field = defaults::Field;

namespace
{

// This test corresponds to the first call of the g_primitive of blake2s(b"hello
// world"). As blake2s first formats the input blocks in 32-bit words in little
// endian, the inputs of the first g_primitive are "lleh" and "ow o"
// ("hello world" -> "hell" "o wo" "rld" plus padding-> "lleh" "ow o" "dlr" plus
// padding)
// The test vectors were computed with the help of blake2s python script from
// https://github.com/buggywhip/blake2_py
TEST(TestG, TestTrue)
{
    libsnark::protoboard<Field> pb;

    libsnark::pb_variable_array<Field> a = variable_array_from_bit_vector(
        pb,
        {
            0, 1, 1, 0, 1, 0, 1, 1, // 6B
            0, 0, 0, 0, 1, 0, 0, 0, // 08
            1, 1, 1, 0, 0, 1, 1, 0, // E6
            0, 1, 0, 0, 0, 1, 1, 1  // 47
        },
        "a");

    libsnark::pb_variable_array<Field> b = variable_array_from_bit_vector(
        pb,
        {
            0, 1, 0, 1, 0, 0, 0, 1, // 51
            0, 0, 0, 0, 1, 1, 1, 0, // 0E
            0, 1, 0, 1, 0, 0, 1, 0, // 52
            0, 1, 1, 1, 1, 1, 1, 1  // 7F
        },
        "b");

    libsnark::pb_variable_array<Field> c = variable_array_from_bit_vector(
        pb,
        {
            0, 1, 1, 0, 1, 0, 1, 0, // 6A
            0, 0, 0, 0, 1, 0, 0, 1, // 09
            1, 1, 1, 0, 0, 1, 1, 0, // E6
            0, 1, 1, 0, 0, 1, 1, 1  // 67
        },
        "c");

    libsnark::pb_variable_array<Field> d = variable_array_from_bit_vector(
        pb,
        {
            0, 1, 0, 1, 0, 0, 0, 1, // 51
            0, 0, 0, 0, 1, 1, 1, 0, // 0E
            0, 1, 0, 1, 0, 0, 1, 0, // 52
            0, 1, 1, 1, 0, 1, 0, 0  // 74
        },
        "d");

    // First word in little endian "lleh"
    libsnark::pb_variable_array<Field> x = variable_array_from_bit_vector(
        pb,
        {
            0, 1, 1, 0, 1, 1, 0, 0, // 6C
            0, 1, 1, 0, 1, 1, 0, 0, // 6C
            0, 1, 1, 0, 0, 1, 0, 1, // 65
            0, 1, 1, 0, 1, 0, 0, 0  // 68
        },
        "x");

    // Second word in little endian "ow o"
    libsnark::pb_variable_array<Field> y = variable_array_from_bit_vector(
        pb,
        {
            0, 1, 1, 0, 1, 1, 1, 1, // 6F
            0, 1, 1, 1, 0, 1, 1, 1, // 77
            0, 0, 1, 0, 0, 0, 0, 0, // 20
            0, 1, 1, 0, 1, 1, 1, 1  // 6F
        },
        "y");

    libsnark::pb_variable_array<Field> a2;
    a2.allocate(pb, BLAKE2s_word_size, "a2");

    libsnark::pb_variable_array<Field> b2;
    b2.allocate(pb, BLAKE2s_word_size, "b2");

    libsnark::pb_variable_array<Field> c2;
    c2.allocate(pb, BLAKE2s_word_size, "c2");

    libsnark::pb_variable_array<Field> d2;
    d2.allocate(pb, BLAKE2s_word_size, "d2");

    g_primitive<Field> g_gadget(pb, a, b, c, d, x, y, a2, b2, c2, d2);
    g_gadget.generate_r1cs_constraints();
    g_gadget.generate_r1cs_witness();

    libsnark::pb_variable_array<Field> a2_expected =
        variable_array_from_bit_vector(
            pb,
            {
                0, 1, 1, 1, 0, 0, 0, 0, // 70
                1, 0, 1, 1, 0, 0, 0, 1, // B1
                0, 0, 1, 1, 0, 1, 0, 1, // 35
                0, 0, 1, 1, 1, 1, 0, 1  // 3D
            },
            "a2_expected");

    libsnark::pb_variable_array<Field> b2_expected =
        variable_array_from_bit_vector(
            pb,
            {
                1, 1, 0, 0, 0, 0, 0, 0, // C0
                0, 1, 1, 1, 1, 1, 1, 1, // 7F
                0, 0, 1, 0, 1, 1, 1, 0, // 2E
                0, 1, 1, 1, 1, 0, 1, 1  // 7B
            },
            "b2_expected");

    libsnark::pb_variable_array<Field> c2_expected =
        variable_array_from_bit_vector(
            pb,
            {
                1, 1, 1, 0, 0, 1, 1, 1, // E7
                0, 0, 1, 0, 0, 0, 0, 1, // 21
                0, 1, 0, 0, 1, 0, 1, 1, // 4B
                0, 1, 0, 0, 0, 0, 0, 0  // 40
            },
            "c2_expected");

    libsnark::pb_variable_array<Field> d2_expected =
        variable_array_from_bit_vector(
            pb,
            {
                1, 0, 1, 1, 0, 0, 0, 0, // B0
                1, 0, 1, 1, 1, 1, 0, 0, // BC
                1, 1, 1, 0, 1, 0, 1, 1, // EB
                0, 1, 0, 0, 1, 1, 0, 0  // 4C
            },
            "d2_expected");

    ASSERT_EQ(a2_expected.get_bits(pb), a2.get_bits(pb));
    ASSERT_EQ(b2_expected.get_bits(pb), b2.get_bits(pb));
    ASSERT_EQ(c2_expected.get_bits(pb), c2.get_bits(pb));
    ASSERT_EQ(d2_expected.get_bits(pb), d2.get_bits(pb));
}

// The test correponds to blake2s(b"hello world")
// The test vectors were computed with hashlib's blake2s function
TEST(TestBlake2sComp, TestTrue)
{
    libsnark::protoboard<Field> pb;

    libsnark::pb_variable<Field> ZERO;
    ZERO.allocate(pb, "zero");
    pb.val(ZERO) = Field::zero();

    // b"hello world" in big endian
    libsnark::pb_variable_array<Field> pb_var_input =
        variable_array_from_bit_vector(
            pb,
            {
                0, 1, 1, 0, 1, 0, 0, 0, // 68
                0, 1, 1, 0, 0, 1, 0, 1, // 65
                0, 1, 1, 0, 1, 1, 0, 0, // 6C
                0, 1, 1, 0, 1, 1, 0, 0, // 6C
                0, 1, 1, 0, 1, 1, 1, 1, // 6F
                0, 0, 1, 0, 0, 0, 0, 0, // 20
                0, 1, 1, 1, 0, 1, 1, 1, // 77
                0, 1, 1, 0, 1, 1, 1, 1, // 6F
                0, 1, 1, 1, 0, 0, 1, 0, // 72
                0, 1, 1, 0, 1, 1, 0, 0, // 6C
                0, 1, 1, 0, 0, 1, 0, 0, // 64
                0, 0, 0, 0, 0, 0, 0, 0, // padding
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            },
            "pb_var_input");

    libsnark::block_variable<Field> input(
        pb, {pb_var_input}, "blake2s_block_input");

    // default chaining value
    libsnark::pb_variable_array<Field> pb_var_h =
        variable_array_from_bit_vector(
            pb,
            {0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1,
             1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0,
             0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0,
             1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1,
             0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1,
             1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1,
             0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1,
             1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1,
             0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1,
             1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0,
             1, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1,
             0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1},
            "pb_var_h");
    libsnark::digest_variable<Field> h(
        pb, BLAKE2s_digest_size, pb_var_h, ZERO, "blake2s_h");

    libsnark::digest_variable<Field> output(pb, BLAKE2s_digest_size, "output");

    BLAKE2s_256_comp<Field> BLAKE2sC_gadget(pb, h, input, output);
    BLAKE2sC_gadget.generate_r1cs_constraints();
    BLAKE2sC_gadget.generate_r1cs_witness(11);

    // blake2s(b"hello world")
    libsnark::pb_variable_array<Field> expected =
        variable_array_from_bit_vector(
            pb,
            {
                1, 0, 0, 1, 1, 0, 1, 0, // 9A
                1, 1, 1, 0, 1, 1, 0, 0, // EC
                0, 1, 1, 0, 1, 0, 0, 0, // 68
                0, 0, 0, 0, 0, 1, 1, 0, // 06
                0, 1, 1, 1, 1, 0, 0, 1, // 79
                0, 1, 0, 0, 0, 1, 0, 1, // 45
                0, 1, 1, 0, 0, 0, 0, 1, // 61
                0, 0, 0, 1, 0, 0, 0, 0, // 10
                0, 1, 1, 1, 1, 1, 1, 0, // 7E
                0, 1, 0, 1, 1, 0, 0, 1, // 59
                0, 1, 0, 0, 1, 0, 1, 1, // 4B
                0, 0, 0, 1, 1, 1, 1, 1, // 1F
                0, 1, 1, 0, 1, 0, 1, 0, // 6A
                1, 0, 0, 0, 1, 0, 1, 0, // 8A
                0, 1, 1, 0, 1, 0, 1, 1, // 6B
                0, 0, 0, 0, 1, 1, 0, 0, // 0C
                1, 0, 0, 1, 0, 0, 1, 0, // 92
                1, 0, 1, 0, 0, 0, 0, 0, // A0
                1, 1, 0, 0, 1, 0, 1, 1, // CB
                1, 0, 1, 0, 1, 0, 0, 1, // A9
                1, 0, 1, 0, 1, 1, 0, 0, // AC
                1, 1, 1, 1, 0, 1, 0, 1, // F5
                1, 1, 1, 0, 0, 1, 0, 1, // E5
                1, 1, 1, 0, 1, 0, 0, 1, // E9
                0, 0, 1, 1, 1, 1, 0, 0, // 3C
                1, 1, 0, 0, 1, 0, 1, 0, // CA
                0, 0, 0, 0, 0, 1, 1, 0, // 06
                1, 1, 1, 1, 0, 1, 1, 1, // F7
                1, 0, 0, 0, 0, 0, 0, 1, // 81
                1, 0, 0, 0, 0, 0, 0, 1, // 81
                0, 0, 1, 1, 1, 0, 1, 1, // 3B
                0, 0, 0, 0, 1, 0, 1, 1  // 0B
            },
            "expected");

    ASSERT_EQ(expected.get_bits(pb), output.bits.get_bits(pb));
}

// The test correponds to blake2s(b"hello world")
// The test vectors were computed with hashlib's blake2s function
TEST(TestBlake2s, TestTrue)
{
    libsnark::protoboard<Field> pb;

    libsnark::pb_variable<Field> ZERO;
    ZERO.allocate(pb, "zero");
    pb.val(ZERO) = Field::zero();

    // b"hello world" in big endian
    libsnark::pb_variable_array<Field> pb_var_input =
        variable_array_from_bit_vector(
            pb,
            {
                0, 1, 1, 0, 1, 0, 0, 0, // 68
                0, 1, 1, 0, 0, 1, 0, 1, // 65
                0, 1, 1, 0, 1, 1, 0, 0, // 6C
                0, 1, 1, 0, 1, 1, 0, 0, // 6C
                0, 1, 1, 0, 1, 1, 1, 1, // 6F
                0, 0, 1, 0, 0, 0, 0, 0, // 20
                0, 1, 1, 1, 0, 1, 1, 1, // 77
                0, 1, 1, 0, 1, 1, 1, 1, // 6F
                0, 1, 1, 1, 0, 0, 1, 0, // 72
                0, 1, 1, 0, 1, 1, 0, 0, // 6C
                0, 1, 1, 0, 0, 1, 0, 0  // 64
            },
            "pb_var_input");

    libsnark::block_variable<Field> input(
        pb, {pb_var_input}, "blake2s_block_input");

    libsnark::digest_variable<Field> output(pb, BLAKE2s_digest_size, "output");

    BLAKE2s_256<Field> blake2s_gadget(pb, input, output);
    blake2s_gadget.generate_r1cs_constraints();
    blake2s_gadget.generate_r1cs_witness();

    // blake2s(b"hello world")
    libsnark::pb_variable_array<Field> expected =
        variable_array_from_bit_vector(
            pb,
            {
                1, 0, 0, 1, 1, 0, 1, 0, // 9A
                1, 1, 1, 0, 1, 1, 0, 0, // EC
                0, 1, 1, 0, 1, 0, 0, 0, // 68
                0, 0, 0, 0, 0, 1, 1, 0, // 06
                0, 1, 1, 1, 1, 0, 0, 1, // 79
                0, 1, 0, 0, 0, 1, 0, 1, // 45
                0, 1, 1, 0, 0, 0, 0, 1, // 61
                0, 0, 0, 1, 0, 0, 0, 0, // 10
                0, 1, 1, 1, 1, 1, 1, 0, // 7E
                0, 1, 0, 1, 1, 0, 0, 1, // 59
                0, 1, 0, 0, 1, 0, 1, 1, // 4B
                0, 0, 0, 1, 1, 1, 1, 1, // 1F
                0, 1, 1, 0, 1, 0, 1, 0, // 6A
                1, 0, 0, 0, 1, 0, 1, 0, // 8A
                0, 1, 1, 0, 1, 0, 1, 1, // 6B
                0, 0, 0, 0, 1, 1, 0, 0, // 0C
                1, 0, 0, 1, 0, 0, 1, 0, // 92
                1, 0, 1, 0, 0, 0, 0, 0, // A0
                1, 1, 0, 0, 1, 0, 1, 1, // CB
                1, 0, 1, 0, 1, 0, 0, 1, // A9
                1, 0, 1, 0, 1, 1, 0, 0, // AC
                1, 1, 1, 1, 0, 1, 0, 1, // F5
                1, 1, 1, 0, 0, 1, 0, 1, // E5
                1, 1, 1, 0, 1, 0, 0, 1, // E9
                0, 0, 1, 1, 1, 1, 0, 0, // 3C
                1, 1, 0, 0, 1, 0, 1, 0, // CA
                0, 0, 0, 0, 0, 1, 1, 0, // 06
                1, 1, 1, 1, 0, 1, 1, 1, // F7
                1, 0, 0, 0, 0, 0, 0, 1, // 81
                1, 0, 0, 0, 0, 0, 0, 1, // 81
                0, 0, 1, 1, 1, 0, 1, 1, // 3B
                0, 0, 0, 0, 1, 0, 1, 1  // 0B
            },
            "expected");

    ASSERT_EQ(expected.get_bits(pb), output.bits.get_bits(pb));
}

// The test correponds to blake2s(b"hello world")
// The test vectors were computed with hashlib's blake2s function
TEST(TestBlake2s, TestTrue2)
{
    libsnark::protoboard<Field> pb;

    libsnark::pb_variable<Field> ZERO;
    ZERO.allocate(pb, "zero");
    pb.val(ZERO) = Field::zero();

    // b"zeth" in big endian
    const std::vector<bool> input_bits = {
        0, 1, 1, 1, 1, 0, 1, 0, // 7A
        0, 1, 1, 0, 0, 1, 0, 1, // 65
        0, 1, 1, 1, 0, 1, 0, 0, // 74
        0, 1, 1, 0, 1, 0, 0, 0, // 68
        0, 1, 1, 1, 1, 0, 1, 0, // 7A
        0, 1, 1, 0, 0, 1, 0, 1, // 65
        0, 1, 1, 1, 0, 1, 0, 0, // 74
        0, 1, 1, 0, 1, 0, 0, 0, // 68
        0, 1, 1, 1, 1, 0, 1, 0, // 7A
        0, 1, 1, 0, 0, 1, 0, 1, // 65
        0, 1, 1, 1, 0, 1, 0, 0, // 74
        0, 1, 1, 0, 1, 0, 0, 0, // 68
        0, 1, 1, 1, 1, 0, 1, 0, // 7A
        0, 1, 1, 0, 0, 1, 0, 1, // 65
        0, 1, 1, 1, 0, 1, 0, 0, // 74
        0, 1, 1, 0, 1, 0, 0, 0, // 68
        0, 1, 1, 1, 1, 0, 1, 0, // 7A
        0, 1, 1, 0, 0, 1, 0, 1, // 65
        0, 1, 1, 1, 0, 1, 0, 0, // 74
        0, 1, 1, 0, 1, 0, 0, 0, // 68
        0, 1, 1, 1, 1, 0, 1, 0, // 7A
        0, 1, 1, 0, 0, 1, 0, 1, // 65
        0, 1, 1, 1, 0, 1, 0, 0, // 74
        0, 1, 1, 0, 1, 0, 0, 0, // 68
        0, 1, 1, 1, 1, 0, 1, 0, // 7A
        0, 1, 1, 0, 0, 1, 0, 1, // 65
        0, 1, 1, 1, 0, 1, 0, 0, // 74
        0, 1, 1, 0, 1, 0, 0, 0, // 68
        0, 1, 1, 1, 1, 0, 1, 0, // 7A
        0, 1, 1, 0, 0, 1, 0, 1, // 65
        0, 1, 1, 1, 0, 1, 0, 0, // 74
        0, 1, 1, 0, 1, 0, 0, 0, // 68
        0, 1, 1, 1, 1, 0, 1, 0, // 7A
        0, 1, 1, 0, 0, 1, 0, 1, // 65
        0, 1, 1, 1, 0, 1, 0, 0, // 74
        0, 1, 1, 0, 1, 0, 0, 0, // 68
        0, 1, 1, 1, 1, 0, 1, 0, // 7A
        0, 1, 1, 0, 0, 1, 0, 1, // 65
        0, 1, 1, 1, 0, 1, 0, 0, // 74
        0, 1, 1, 0, 1, 0, 0, 0, // 68
        0, 1, 1, 1, 1, 0, 1, 0, // 7A
        0, 1, 1, 0, 0, 1, 0, 1, // 65
        0, 1, 1, 1, 0, 1, 0, 0, // 74
        0, 1, 1, 0, 1, 0, 0, 0, // 68
        0, 1, 1, 1, 1, 0, 1, 0, // 7A
        0, 1, 1, 0, 0, 1, 0, 1, // 65
        0, 1, 1, 1, 0, 1, 0, 0, // 74
        0, 1, 1, 0, 1, 0, 0, 0, // 68
        0, 1, 1, 1, 1, 0, 1, 0, // 7A
        0, 1, 1, 0, 0, 1, 0, 1, // 65
        0, 1, 1, 1, 0, 1, 0, 0, // 74
        0, 1, 1, 0, 1, 0, 0, 0, // 68
        0, 1, 1, 1, 1, 0, 1, 0, // 7A
        0, 1, 1, 0, 0, 1, 0, 1, // 65
        0, 1, 1, 1, 0, 1, 0, 0, // 74
        0, 1, 1, 0, 1, 0, 0, 0, // 68
        0, 1, 1, 1, 1, 0, 1, 0, // 7A
        0, 1, 1, 0, 0, 1, 0, 1, // 65
        0, 1, 1, 1, 0, 1, 0, 0, // 74
        0, 1, 1, 0, 1, 0, 0, 0, // 68
        0, 1, 1, 1, 1, 0, 1, 0, // 7A
        0, 1, 1, 0, 0, 1, 0, 1, // 65
        0, 1, 1, 1, 0, 1, 0, 0, // 74
        0, 1, 1, 0, 1, 0, 0, 0, // 68
        0, 1, 1, 1, 1, 0, 1, 0, // 7A
        0, 1, 1, 0, 0, 1, 0, 1, // 65
        0, 1, 1, 1, 0, 1, 0, 0, // 74
        0, 1, 1, 0, 1, 0, 0, 0, // 68
        0, 1, 1, 1, 1, 0, 1, 0, // 7A
        0, 1, 1, 0, 0, 1, 0, 1, // 65
        0, 1, 1, 1, 0, 1, 0, 0, // 74
        0, 1, 1, 0, 1, 0, 0, 0, // 68
        0, 1, 1, 1, 1, 0, 1, 0, // 7A
        0, 1, 1, 0, 0, 1, 0, 1, // 65
        0, 1, 1, 1, 0, 1, 0, 0, // 74
        0, 1, 1, 0, 1, 0, 0, 0, // 68
        0, 1, 1, 1, 1, 0, 1, 0, // 7A
        0, 1, 1, 0, 0, 1, 0, 1, // 65
        0, 1, 1, 1, 0, 1, 0, 0, // 74
        0, 1, 1, 0, 1, 0, 0, 0, // 68
        0, 1, 1, 1, 1, 0, 1, 0, // 7A
        0, 1, 1, 0, 0, 1, 0, 1, // 65
        0, 1, 1, 1, 0, 1, 0, 0, // 74
        0, 1, 1, 0, 1, 0, 0, 0, // 68
        0, 1, 1, 1, 1, 0, 1, 0, // 7A
        0, 1, 1, 0, 0, 1, 0, 1, // 65
        0, 1, 1, 1, 0, 1, 0, 0, // 74
        0, 1, 1, 0, 1, 0, 0, 0, // 68
        0, 1, 1, 1, 1, 0, 1, 0, // 7A
        0, 1, 1, 0, 0, 1, 0, 1, // 65
        0, 1, 1, 1, 0, 1, 0, 0, // 74
        0, 1, 1, 0, 1, 0, 0, 0, // 68
        0, 1, 1, 1, 1, 0, 1, 0, // 7A
        0, 1, 1, 0, 0, 1, 0, 1, // 65
        0, 1, 1, 1, 0, 1, 0, 0, // 74
        0, 1, 1, 0, 1, 0, 0, 0, // 68
        0, 1, 1, 1, 1, 0, 1, 0, // 7A
        0, 1, 1, 0, 0, 1, 0, 1, // 65
        0, 1, 1, 1, 0, 1, 0, 0, // 74
        0, 1, 1, 0, 1, 0, 0, 0, // 68
        0, 1, 1, 1, 1, 0, 1, 0, // 7A
        0, 1, 1, 0, 0, 1, 0, 1, // 65
        0, 1, 1, 1, 0, 1, 0, 0, // 74
        0, 1, 1, 0, 1, 0, 0, 0, // 68
        0, 1, 1, 1, 1, 0, 1, 0, // 7A
        0, 1, 1, 0, 0, 1, 0, 1, // 65
        0, 1, 1, 1, 0, 1, 0, 0, // 74
        0, 1, 1, 0, 1, 0, 0, 0, // 68
        0, 1, 1, 1, 1, 0, 1, 0, // 7A
        0, 1, 1, 0, 0, 1, 0, 1, // 65
        0, 1, 1, 1, 0, 1, 0, 0, // 74
        0, 1, 1, 0, 1, 0, 0, 0, // 68
        0, 1, 1, 1, 1, 0, 1, 0, // 7A
        0, 1, 1, 0, 0, 1, 0, 1, // 65
        0, 1, 1, 1, 0, 1, 0, 0, // 74
        0, 1, 1, 0, 1, 0, 0, 0, // 68
        0, 1, 1, 1, 1, 0, 1, 0, // 7A
        0, 1, 1, 0, 0, 1, 0, 1, // 65
        0, 1, 1, 1, 0, 1, 0, 0, // 74
        0, 1, 1, 0, 1, 0, 0, 0, // 68
        0, 1, 1, 1, 1, 0, 1, 0, // 7A
        0, 1, 1, 0, 0, 1, 0, 1, // 65
        0, 1, 1, 1, 0, 1, 0, 0, // 74
        0, 1, 1, 0, 1, 0, 0, 0, // 68
        0, 1, 1, 1, 1, 0, 1, 0, // 7A
        0, 1, 1, 0, 0, 1, 0, 1, // 65
        0, 1, 1, 1, 0, 1, 0, 0, // 74
        0, 1, 1, 0, 1, 0, 0, 0  // 68
    };
    libsnark::pb_variable_array<Field> input_vars =
        variable_array_from_bit_vector(pb, input_bits, "input_vars");

    libsnark::block_variable<Field> input(
        pb, {input_vars}, "blake2s_block_input");

    libsnark::digest_variable<Field> output(pb, BLAKE2s_digest_size, "output");

    BLAKE2s_256<Field> blake2s_gadget(pb, input, output);
    blake2s_gadget.generate_r1cs_constraints();
    blake2s_gadget.generate_r1cs_witness();

    // blake2s(b"zeth")
    bits256 expected = bits256::from_hex(
        "b5f199b422df36c99363725d886e64c07ffd8852063adbbfbb86f43716ffab0e");

    ASSERT_EQ(expected.to_vector(), output.bits.get_bits(pb));
    ASSERT_EQ(expected.to_vector(), BLAKE2s_256<Field>::get_hash(input_bits));
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
