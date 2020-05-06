// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/circuits/blake2s/blake2s.hpp"
#include "libzeth/circuits/blake2s/g_primitive.hpp"
#include "libzeth/circuits/circuit_types.hpp"
#include "libzeth/circuits/circuit_utils.hpp"
#include "libzeth/core/utils.hpp"

#include <gtest/gtest.h>

using namespace libsnark;
using namespace libzeth;

using ppT = libzeth::ppT;
using FieldT = libff::Fr<ppT>;

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
    libsnark::protoboard<FieldT> pb;

    libsnark::pb_variable<FieldT> zero;
    zero.allocate(pb, "zero");
    pb.val(zero) = FieldT::zero();

    libsnark::pb_variable_array<FieldT> a = variable_array_from_bit_vector(
        {
            false, true,  true,  false, true,  false, true,  true,  // 6B
            false, false, false, false, true,  false, false, false, // 08
            true,  true,  true,  false, false, true,  true,  false, // E6
            false, true,  false, false, false, true,  true,  true   // 47
        },
        zero);

    libsnark::pb_variable_array<FieldT> b = variable_array_from_bit_vector(
        {
            false, true,  false, true,  false, false, false, true,  // 51
            false, false, false, false, true,  true,  true,  false, // 0E
            false, true,  false, true,  false, false, true,  false, // 52
            false, true,  true,  true,  true,  true,  true,  true   // 7F
        },
        zero);

    libsnark::pb_variable_array<FieldT> c = variable_array_from_bit_vector(
        {
            false, true,  true,  false, true,  false, true,  false, // 6A
            false, false, false, false, true,  false, false, true,  // 09
            true,  true,  true,  false, false, true,  true,  false, // E6
            false, true,  true,  false, false, true,  true,  true   // 67
        },
        zero);

    libsnark::pb_variable_array<FieldT> d = variable_array_from_bit_vector(
        {
            false, true,  false, true,  false, false, false, true,  // 51
            false, false, false, false, true,  true,  true,  false, // 0E
            false, true,  false, true,  false, false, true,  false, // 52
            false, true,  true,  true,  false, true,  false, false  // 74
        },
        zero);

    // First word in little endian "lleh"
    libsnark::pb_variable_array<FieldT> x = variable_array_from_bit_vector(
        {
            false, true, true, false, true,  true,  false, false, // 6C
            false, true, true, false, true,  true,  false, false, // 6C
            false, true, true, false, false, true,  false, true,  // 65
            false, true, true, false, true,  false, false, false  // 68
        },
        zero);

    // Second word in little endian "ow o"
    libsnark::pb_variable_array<FieldT> y = variable_array_from_bit_vector(
        {
            false, true,  true, false, true,  true,  true,  true,  // 6F
            false, true,  true, true,  false, true,  true,  true,  // 77
            false, false, true, false, false, false, false, false, // 20
            false, true,  true, false, true,  true,  true,  true   // 6F
        },
        zero);

    libsnark::pb_variable_array<FieldT> a2;
    a2.allocate(pb, BLAKE2s_word_size, "a2");

    libsnark::pb_variable_array<FieldT> b2;
    b2.allocate(pb, BLAKE2s_word_size, "b2");

    libsnark::pb_variable_array<FieldT> c2;
    c2.allocate(pb, BLAKE2s_word_size, "c2");

    libsnark::pb_variable_array<FieldT> d2;
    d2.allocate(pb, BLAKE2s_word_size, "d2");

    g_primitive<FieldT> g_gadget(pb, a, b, c, d, x, y, a2, b2, c2, d2);
    g_gadget.generate_r1cs_constraints();
    g_gadget.generate_r1cs_witness();

    libsnark::pb_variable_array<FieldT> a2_expected =
        variable_array_from_bit_vector(
            {
                false, true,  true, true, false, false, false, false, // 70
                true,  false, true, true, false, false, false, true,  // B1
                false, false, true, true, false, true,  false, true,  // 35
                false, false, true, true, true,  true,  false, true   // 3D
            },
            zero);

    libsnark::pb_variable_array<FieldT> b2_expected =
        variable_array_from_bit_vector(
            {
                true,  true,  false, false, false, false, false, false, // C0
                false, true,  true,  true,  true,  true,  true,  true,  // 7F
                false, false, true,  false, true,  true,  true,  false, // 2E
                false, true,  true,  true,  true,  false, true,  true   // 7B
            },
            zero);

    libsnark::pb_variable_array<FieldT> c2_expected =
        variable_array_from_bit_vector(
            {
                true,  true,  true,  false, false, true,  true,  true, // E7
                false, false, true,  false, false, false, false, true, // 21
                false, true,  false, false, true,  false, true,  true, // 4B
                false, true,  false, false, false, false, false, false // 40
            },
            zero);

    libsnark::pb_variable_array<FieldT> d2_expected =
        variable_array_from_bit_vector(
            {
                true,  false, true,  true,  false, false, false, false, // B0
                true,  false, true,  true,  true,  true,  false, false, // BC
                true,  true,  true,  false, true,  false, true,  true,  // EB
                false, true,  false, false, true,  true,  false, false  // 4C
            },
            zero);

    ASSERT_EQ(a2_expected.get_bits(pb), a2.get_bits(pb));
    ASSERT_EQ(b2_expected.get_bits(pb), b2.get_bits(pb));
    ASSERT_EQ(c2_expected.get_bits(pb), c2.get_bits(pb));
    ASSERT_EQ(d2_expected.get_bits(pb), d2.get_bits(pb));
}

// The test correponds to blake2s(b"hello world")
// The test vectors were computed with hashlib's blake2s function
TEST(TestBlake2sComp, TestTrue)
{
    libsnark::protoboard<FieldT> pb;

    libsnark::pb_variable<FieldT> zero;
    zero.allocate(pb, "zero");
    pb.val(zero) = FieldT::zero();

    // b"hello world" in big endian
    libsnark::pb_variable_array<FieldT>
        pb_var_input =
            variable_array_from_bit_vector(
                {
                    false, true,  true,  false, true,  false, false,
                    false, // 68
                    false, true,  true,  false, false, true,  false,
                    true, // 65
                    false, true,  true,  false, true,  true,  false,
                    false, // 6C
                    false, true,  true,  false, true,  true,  false,
                    false, // 6C
                    false, true,  true,  false, true,  true,  true,
                    true, // 6F
                    false, false, true,  false, false, false, false,
                    false, // 20
                    false, true,  true,  true,  false, true,  true,
                    true, // 77
                    false, true,  true,  false, true,  true,  true,
                    true, // 6F
                    false, true,  true,  true,  false, false, true,
                    false, // 72
                    false, true,  true,  false, true,  true,  false,
                    false, // 6C
                    false, true,  true,  false, false, true,  false,
                    false, // 64
                    false, false, false, false, false, false, false,
                    false, // padding
                    false, false, false, false, false, false, false,
                    false, false, false, false, false, false, false,
                    false, false, false, false, false, false, false,
                    false, false, false, false, false, false, false,
                    false, false, false, false, false, false, false,
                    false, false, false, false, false, false, false,
                    false, false, false, false, false, false, false,
                    false, false, false, false, false, false, false,
                    false, false, false, false, false, false, false,
                    false, false, false, false, false, false, false,
                    false, false, false, false, false, false, false,
                    false, false, false, false, false, false, false,
                    false, false, false, false, false, false, false,
                    false, false, false, false, false, false, false,
                    false, false, false, false, false, false, false,
                    false, false, false, false, false, false, false,
                    false, false, false, false, false, false, false,
                    false, false, false, false, false, false, false,
                    false, false, false, false, false, false, false,
                    false, false, false, false, false, false, false,
                    false, false, false, false, false, false, false,
                    false, false, false, false, false, false, false,
                    false, false, false, false, false, false,
                },
                zero);

    libsnark::block_variable<FieldT> input(
        pb, {pb_var_input}, "blake2s_block_input");

    // default chaining value
    libsnark::pb_variable_array<FieldT> pb_var_h =
        variable_array_from_bit_vector(
            {false, true,  true,  false, true,  false, true,  true,  false,
             false, false, false, true,  false, false, false, true,  true,
             true,  false, false, true,  true,  false, false, true,  false,
             false, false, true,  true,  true,  true,  false, true,  true,
             true,  false, true,  true,  false, true,  true,  false, false,
             true,  true,  true,  true,  false, true,  false, true,  true,
             true,  false, true,  false, false, false, false, true,  false,
             true,  false, false, true,  true,  true,  true,  false, false,
             false, true,  true,  false, true,  true,  true,  false, true,
             true,  true,  true,  false, false, true,  true,  false, true,
             true,  true,  false, false, true,  false, true,  false, true,
             false, false, true,  false, true,  false, true,  false, false,
             true,  true,  true,  true,  true,  true,  true,  true,  false,
             true,  false, true,  false, false, true,  true,  true,  false,
             true,  false, false, true,  false, true,  false, false, false,
             true,  false, false, false, false, true,  true,  true,  false,
             false, true,  false, true,  false, false, true,  false, false,
             true,  true,  true,  true,  true,  true,  true,  true,  false,
             false, true,  true,  false, true,  true,  false, false, false,
             false, false, true,  false, true,  false, true,  true,  false,
             true,  false, false, false, true,  false, false, false, true,
             true,  false, false, false, false, false, true,  true,  true,
             true,  true,  true,  false, false, false, false, false, true,
             true,  true,  true,  false, true,  true,  false, false, true,
             true,  false, true,  false, true,  false, true,  true,  false,
             true,  false, true,  true,  false, true,  true,  true,  true,
             true,  false, false, false, false, false, true,  true,  false,
             false, true,  true,  false, true,  false, false, false, true,
             true,  false, false, true},
            zero);
    libsnark::digest_variable<FieldT> h(
        pb, BLAKE2s_digest_size, pb_var_h, zero, "blake2s_h");

    libsnark::digest_variable<FieldT> output(pb, BLAKE2s_digest_size, "output");

    BLAKE2s_256_comp<FieldT> blak_e2s_c_gadget(pb, h, input, output);
    blak_e2s_c_gadget.generate_r1cs_constraints();
    blak_e2s_c_gadget.generate_r1cs_witness(11);

    // blake2s(b"hello world")
    libsnark::pb_variable_array<FieldT> expected =
        variable_array_from_bit_vector(
            {
                true,  false, false, true,  true,  false, true,  false, // 9A
                true,  true,  true,  false, true,  true,  false, false, // EC
                false, true,  true,  false, true,  false, false, false, // 68
                false, false, false, false, false, true,  true,  false, // 06
                false, true,  true,  true,  true,  false, false, true,  // 79
                false, true,  false, false, false, true,  false, true,  // 45
                false, true,  true,  false, false, false, false, true,  // 61
                false, false, false, true,  false, false, false, false, // 10
                false, true,  true,  true,  true,  true,  true,  false, // 7E
                false, true,  false, true,  true,  false, false, true,  // 59
                false, true,  false, false, true,  false, true,  true,  // 4B
                false, false, false, true,  true,  true,  true,  true,  // 1F
                false, true,  true,  false, true,  false, true,  false, // 6A
                true,  false, false, false, true,  false, true,  false, // 8A
                false, true,  true,  false, true,  false, true,  true,  // 6B
                false, false, false, false, true,  true,  false, false, // 0C
                true,  false, false, true,  false, false, true,  false, // 92
                true,  false, true,  false, false, false, false, false, // A0
                true,  true,  false, false, true,  false, true,  true,  // CB
                true,  false, true,  false, true,  false, false, true,  // A9
                true,  false, true,  false, true,  true,  false, false, // AC
                true,  true,  true,  true,  false, true,  false, true,  // F5
                true,  true,  true,  false, false, true,  false, true,  // E5
                true,  true,  true,  false, true,  false, false, true,  // E9
                false, false, true,  true,  true,  true,  false, false, // 3C
                true,  true,  false, false, true,  false, true,  false, // CA
                false, false, false, false, false, true,  true,  false, // 06
                true,  true,  true,  true,  false, true,  true,  true,  // F7
                true,  false, false, false, false, false, false, true,  // 81
                true,  false, false, false, false, false, false, true,  // 81
                false, false, true,  true,  true,  false, true,  true,  // 3B
                false, false, false, false, true,  false, true,  true   // 0B
            },
            zero);

    ASSERT_EQ(expected.get_bits(pb), output.bits.get_bits(pb));
}

// The test correponds to blake2s(b"hello world")
// The test vectors were computed with hashlib's blake2s function
TEST(TestBlake2s, TestTrue)
{
    libsnark::protoboard<FieldT> pb;

    libsnark::pb_variable<FieldT> zero;
    zero.allocate(pb, "zero");
    pb.val(zero) = FieldT::zero();

    // b"hello world" in big endian
    libsnark::pb_variable_array<FieldT> pb_var_input =
        variable_array_from_bit_vector(
            {
                false, true,  true, false, true,  false, false, false, // 68
                false, true,  true, false, false, true,  false, true,  // 65
                false, true,  true, false, true,  true,  false, false, // 6C
                false, true,  true, false, true,  true,  false, false, // 6C
                false, true,  true, false, true,  true,  true,  true,  // 6F
                false, false, true, false, false, false, false, false, // 20
                false, true,  true, true,  false, true,  true,  true,  // 77
                false, true,  true, false, true,  true,  true,  true,  // 6F
                false, true,  true, true,  false, false, true,  false, // 72
                false, true,  true, false, true,  true,  false, false, // 6C
                false, true,  true, false, false, true,  false, false  // 64
            },
            zero);

    libsnark::block_variable<FieldT> input(
        pb, {pb_var_input}, "blake2s_block_input");

    libsnark::digest_variable<FieldT> output(pb, BLAKE2s_digest_size, "output");

    BLAKE2s_256<FieldT> blake2s_gadget(pb, input, output);
    blake2s_gadget.generate_r1cs_constraints();
    blake2s_gadget.generate_r1cs_witness();

    // blake2s(b"hello world")
    libsnark::pb_variable_array<FieldT> expected =
        variable_array_from_bit_vector(
            {
                true,  false, false, true,  true,  false, true,  false, // 9A
                true,  true,  true,  false, true,  true,  false, false, // EC
                false, true,  true,  false, true,  false, false, false, // 68
                false, false, false, false, false, true,  true,  false, // 06
                false, true,  true,  true,  true,  false, false, true,  // 79
                false, true,  false, false, false, true,  false, true,  // 45
                false, true,  true,  false, false, false, false, true,  // 61
                false, false, false, true,  false, false, false, false, // 10
                false, true,  true,  true,  true,  true,  true,  false, // 7E
                false, true,  false, true,  true,  false, false, true,  // 59
                false, true,  false, false, true,  false, true,  true,  // 4B
                false, false, false, true,  true,  true,  true,  true,  // 1F
                false, true,  true,  false, true,  false, true,  false, // 6A
                true,  false, false, false, true,  false, true,  false, // 8A
                false, true,  true,  false, true,  false, true,  true,  // 6B
                false, false, false, false, true,  true,  false, false, // 0C
                true,  false, false, true,  false, false, true,  false, // 92
                true,  false, true,  false, false, false, false, false, // A0
                true,  true,  false, false, true,  false, true,  true,  // CB
                true,  false, true,  false, true,  false, false, true,  // A9
                true,  false, true,  false, true,  true,  false, false, // AC
                true,  true,  true,  true,  false, true,  false, true,  // F5
                true,  true,  true,  false, false, true,  false, true,  // E5
                true,  true,  true,  false, true,  false, false, true,  // E9
                false, false, true,  true,  true,  true,  false, false, // 3C
                true,  true,  false, false, true,  false, true,  false, // CA
                false, false, false, false, false, true,  true,  false, // 06
                true,  true,  true,  true,  false, true,  true,  true,  // F7
                true,  false, false, false, false, false, false, true,  // 81
                true,  false, false, false, false, false, false, true,  // 81
                false, false, true,  true,  true,  false, true,  true,  // 3B
                false, false, false, false, true,  false, true,  true   // 0B
            },
            zero);

    ASSERT_EQ(expected.get_bits(pb), output.bits.get_bits(pb));
}

// The test correponds to blake2s(b"hello world")
// The test vectors were computed with hashlib's blake2s function
TEST(TestBlake2s, TestTrue2)
{
    libsnark::protoboard<FieldT> pb;

    libsnark::pb_variable<FieldT> zero;
    zero.allocate(pb, "zero");
    pb.val(zero) = FieldT::zero();

    // b"zeth" in big endian
    libsnark::pb_variable_array<FieldT> pb_var_input =
        variable_array_from_bit_vector(
            {
                false, true, true, true,  true,  false, true,  false, // 7A
                false, true, true, false, false, true,  false, true,  // 65
                false, true, true, true,  false, true,  false, false, // 74
                false, true, true, false, true,  false, false, false, // 68
                false, true, true, true,  true,  false, true,  false, // 7A
                false, true, true, false, false, true,  false, true,  // 65
                false, true, true, true,  false, true,  false, false, // 74
                false, true, true, false, true,  false, false, false, // 68
                false, true, true, true,  true,  false, true,  false, // 7A
                false, true, true, false, false, true,  false, true,  // 65
                false, true, true, true,  false, true,  false, false, // 74
                false, true, true, false, true,  false, false, false, // 68
                false, true, true, true,  true,  false, true,  false, // 7A
                false, true, true, false, false, true,  false, true,  // 65
                false, true, true, true,  false, true,  false, false, // 74
                false, true, true, false, true,  false, false, false, // 68
                false, true, true, true,  true,  false, true,  false, // 7A
                false, true, true, false, false, true,  false, true,  // 65
                false, true, true, true,  false, true,  false, false, // 74
                false, true, true, false, true,  false, false, false, // 68
                false, true, true, true,  true,  false, true,  false, // 7A
                false, true, true, false, false, true,  false, true,  // 65
                false, true, true, true,  false, true,  false, false, // 74
                false, true, true, false, true,  false, false, false, // 68
                false, true, true, true,  true,  false, true,  false, // 7A
                false, true, true, false, false, true,  false, true,  // 65
                false, true, true, true,  false, true,  false, false, // 74
                false, true, true, false, true,  false, false, false, // 68
                false, true, true, true,  true,  false, true,  false, // 7A
                false, true, true, false, false, true,  false, true,  // 65
                false, true, true, true,  false, true,  false, false, // 74
                false, true, true, false, true,  false, false, false, // 68
                false, true, true, true,  true,  false, true,  false, // 7A
                false, true, true, false, false, true,  false, true,  // 65
                false, true, true, true,  false, true,  false, false, // 74
                false, true, true, false, true,  false, false, false, // 68
                false, true, true, true,  true,  false, true,  false, // 7A
                false, true, true, false, false, true,  false, true,  // 65
                false, true, true, true,  false, true,  false, false, // 74
                false, true, true, false, true,  false, false, false, // 68
                false, true, true, true,  true,  false, true,  false, // 7A
                false, true, true, false, false, true,  false, true,  // 65
                false, true, true, true,  false, true,  false, false, // 74
                false, true, true, false, true,  false, false, false, // 68
                false, true, true, true,  true,  false, true,  false, // 7A
                false, true, true, false, false, true,  false, true,  // 65
                false, true, true, true,  false, true,  false, false, // 74
                false, true, true, false, true,  false, false, false, // 68
                false, true, true, true,  true,  false, true,  false, // 7A
                false, true, true, false, false, true,  false, true,  // 65
                false, true, true, true,  false, true,  false, false, // 74
                false, true, true, false, true,  false, false, false, // 68
                false, true, true, true,  true,  false, true,  false, // 7A
                false, true, true, false, false, true,  false, true,  // 65
                false, true, true, true,  false, true,  false, false, // 74
                false, true, true, false, true,  false, false, false, // 68
                false, true, true, true,  true,  false, true,  false, // 7A
                false, true, true, false, false, true,  false, true,  // 65
                false, true, true, true,  false, true,  false, false, // 74
                false, true, true, false, true,  false, false, false, // 68
                false, true, true, true,  true,  false, true,  false, // 7A
                false, true, true, false, false, true,  false, true,  // 65
                false, true, true, true,  false, true,  false, false, // 74
                false, true, true, false, true,  false, false, false, // 68
                false, true, true, true,  true,  false, true,  false, // 7A
                false, true, true, false, false, true,  false, true,  // 65
                false, true, true, true,  false, true,  false, false, // 74
                false, true, true, false, true,  false, false, false, // 68
                false, true, true, true,  true,  false, true,  false, // 7A
                false, true, true, false, false, true,  false, true,  // 65
                false, true, true, true,  false, true,  false, false, // 74
                false, true, true, false, true,  false, false, false, // 68
                false, true, true, true,  true,  false, true,  false, // 7A
                false, true, true, false, false, true,  false, true,  // 65
                false, true, true, true,  false, true,  false, false, // 74
                false, true, true, false, true,  false, false, false, // 68
                false, true, true, true,  true,  false, true,  false, // 7A
                false, true, true, false, false, true,  false, true,  // 65
                false, true, true, true,  false, true,  false, false, // 74
                false, true, true, false, true,  false, false, false, // 68
                false, true, true, true,  true,  false, true,  false, // 7A
                false, true, true, false, false, true,  false, true,  // 65
                false, true, true, true,  false, true,  false, false, // 74
                false, true, true, false, true,  false, false, false, // 68
                false, true, true, true,  true,  false, true,  false, // 7A
                false, true, true, false, false, true,  false, true,  // 65
                false, true, true, true,  false, true,  false, false, // 74
                false, true, true, false, true,  false, false, false, // 68
                false, true, true, true,  true,  false, true,  false, // 7A
                false, true, true, false, false, true,  false, true,  // 65
                false, true, true, true,  false, true,  false, false, // 74
                false, true, true, false, true,  false, false, false, // 68
                false, true, true, true,  true,  false, true,  false, // 7A
                false, true, true, false, false, true,  false, true,  // 65
                false, true, true, true,  false, true,  false, false, // 74
                false, true, true, false, true,  false, false, false, // 68
                false, true, true, true,  true,  false, true,  false, // 7A
                false, true, true, false, false, true,  false, true,  // 65
                false, true, true, true,  false, true,  false, false, // 74
                false, true, true, false, true,  false, false, false, // 68
                false, true, true, true,  true,  false, true,  false, // 7A
                false, true, true, false, false, true,  false, true,  // 65
                false, true, true, true,  false, true,  false, false, // 74
                false, true, true, false, true,  false, false, false, // 68
                false, true, true, true,  true,  false, true,  false, // 7A
                false, true, true, false, false, true,  false, true,  // 65
                false, true, true, true,  false, true,  false, false, // 74
                false, true, true, false, true,  false, false, false, // 68
                false, true, true, true,  true,  false, true,  false, // 7A
                false, true, true, false, false, true,  false, true,  // 65
                false, true, true, true,  false, true,  false, false, // 74
                false, true, true, false, true,  false, false, false, // 68
                false, true, true, true,  true,  false, true,  false, // 7A
                false, true, true, false, false, true,  false, true,  // 65
                false, true, true, true,  false, true,  false, false, // 74
                false, true, true, false, true,  false, false, false, // 68
                false, true, true, true,  true,  false, true,  false, // 7A
                false, true, true, false, false, true,  false, true,  // 65
                false, true, true, true,  false, true,  false, false, // 74
                false, true, true, false, true,  false, false, false, // 68
                false, true, true, true,  true,  false, true,  false, // 7A
                false, true, true, false, false, true,  false, true,  // 65
                false, true, true, true,  false, true,  false, false, // 74
                false, true, true, false, true,  false, false, false, // 68
                false, true, true, true,  true,  false, true,  false, // 7A
                false, true, true, false, false, true,  false, true,  // 65
                false, true, true, true,  false, true,  false, false, // 74
                false, true, true, false, true,  false, false, false  // 68
            },
            zero);

    libsnark::block_variable<FieldT> input(
        pb, {pb_var_input}, "blake2s_block_input");

    libsnark::digest_variable<FieldT> output(pb, BLAKE2s_digest_size, "output");

    BLAKE2s_256<FieldT> blake2s_gadget(pb, input, output);
    blake2s_gadget.generate_r1cs_constraints();
    blake2s_gadget.generate_r1cs_witness();

    // blake2s(b"zeth")
    bits256 expected = bits256_from_hex(
        "b5f199b422df36c99363725d886e64c07ffd8852063adbbfbb86f43716ffab0e");

    ASSERT_EQ(bits256_to_vector(expected), output.bits.get_bits(pb));
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
