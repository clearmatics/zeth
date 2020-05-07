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
            0, 1, 1, 0, 1, 0, 1, 1, // 6B // NOLINT
            0, 0, 0, 0, 1, 0, 0, 0, // 08 // NOLINT
            1, 1, 1, 0, 0, 1, 1, 0, // E6 // NOLINT
            0, 1, 0, 0, 0, 1, 1, 1  // 47 // NOLINT
        },
        zero);

    libsnark::pb_variable_array<FieldT> b = variable_array_from_bit_vector(
        {
            0, 1, 0, 1, 0, 0, 0, 1, // 51 // NOLINT
            0, 0, 0, 0, 1, 1, 1, 0, // 0E // NOLINT
            0, 1, 0, 1, 0, 0, 1, 0, // 52 // NOLINT
            0, 1, 1, 1, 1, 1, 1, 1  // 7F // NOLINT
        },
        zero);

    libsnark::pb_variable_array<FieldT> c = variable_array_from_bit_vector(
        {
            0, 1, 1, 0, 1, 0, 1, 0, // 6A // NOLINT
            0, 0, 0, 0, 1, 0, 0, 1, // 09 // NOLINT
            1, 1, 1, 0, 0, 1, 1, 0, // E6 // NOLINT
            0, 1, 1, 0, 0, 1, 1, 1  // 67 // NOLINT
        },
        zero);

    libsnark::pb_variable_array<FieldT> d = variable_array_from_bit_vector(
        {
            0, 1, 0, 1, 0, 0, 0, 1, // 51 // NOLINT
            0, 0, 0, 0, 1, 1, 1, 0, // 0E // NOLINT
            0, 1, 0, 1, 0, 0, 1, 0, // 52 // NOLINT
            0, 1, 1, 1, 0, 1, 0, 0  // 74 // NOLINT
        },
        zero);

    // First word in little endian "lleh"
    libsnark::pb_variable_array<FieldT> x = variable_array_from_bit_vector(
        {
            0, 1, 1, 0, 1, 1, 0, 0, // 6C // NOLINT
            0, 1, 1, 0, 1, 1, 0, 0, // 6C // NOLINT
            0, 1, 1, 0, 0, 1, 0, 1, // 65 // NOLINT
            0, 1, 1, 0, 1, 0, 0, 0  // 68 // NOLINT
        },
        zero);

    // Second word in little endian "ow o"
    libsnark::pb_variable_array<FieldT> y = variable_array_from_bit_vector(
        {
            0, 1, 1, 0, 1, 1, 1, 1, // 6F // NOLINT
            0, 1, 1, 1, 0, 1, 1, 1, // 77 // NOLINT
            0, 0, 1, 0, 0, 0, 0, 0, // 20 // NOLINT
            0, 1, 1, 0, 1, 1, 1, 1  // 6F // NOLINT
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
                0, 1, 1, 1, 0, 0, 0, 0, // 70 // NOLINT
                1, 0, 1, 1, 0, 0, 0, 1, // B1 // NOLINT
                0, 0, 1, 1, 0, 1, 0, 1, // 35 // NOLINT
                0, 0, 1, 1, 1, 1, 0, 1  // 3D // NOLINT
            },
            zero);

    libsnark::pb_variable_array<FieldT> b2_expected =
        variable_array_from_bit_vector(
            {
                1, 1, 0, 0, 0, 0, 0, 0, // C0 // NOLINT
                0, 1, 1, 1, 1, 1, 1, 1, // 7F // NOLINT
                0, 0, 1, 0, 1, 1, 1, 0, // 2E // NOLINT
                0, 1, 1, 1, 1, 0, 1, 1  // 7B // NOLINT
            },
            zero);

    libsnark::pb_variable_array<FieldT> c2_expected =
        variable_array_from_bit_vector(
            {
                1, 1, 1, 0, 0, 1, 1, 1, // E7 // NOLINT
                0, 0, 1, 0, 0, 0, 0, 1, // 21 // NOLINT
                0, 1, 0, 0, 1, 0, 1, 1, // 4B // NOLINT
                0, 1, 0, 0, 0, 0, 0, 0  // 40 // NOLINT
            },
            zero);

    libsnark::pb_variable_array<FieldT> d2_expected =
        variable_array_from_bit_vector(
            {
                1, 0, 1, 1, 0, 0, 0, 0, // B0 // NOLINT
                1, 0, 1, 1, 1, 1, 0, 0, // BC // NOLINT
                1, 1, 1, 0, 1, 0, 1, 1, // EB // NOLINT
                0, 1, 0, 0, 1, 1, 0, 0  // 4C // NOLINT
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
    libsnark::pb_variable_array<FieldT> pb_var_input =
        variable_array_from_bit_vector(
            {
                0, 1, 1, 0, 1, 0, 0, 0, // 68 // NOLINT
                0, 1, 1, 0, 0, 1, 0, 1, // 65 // NOLINT
                0, 1, 1, 0, 1, 1, 0, 0, // 6C // NOLINT
                0, 1, 1, 0, 1, 1, 0, 0, // 6C // NOLINT
                0, 1, 1, 0, 1, 1, 1, 1, // 6F // NOLINT
                0, 0, 1, 0, 0, 0, 0, 0, // 20 // NOLINT
                0, 1, 1, 1, 0, 1, 1, 1, // 77 // NOLINT
                0, 1, 1, 0, 1, 1, 1, 1, // 6F // NOLINT
                0, 1, 1, 1, 0, 0, 1, 0, // 72 // NOLINT
                0, 1, 1, 0, 1, 1, 0, 0, // 6C // NOLINT
                0, 1, 1, 0, 0, 1, 0, 0, // 64 // NOLINT
                0, 0, 0, 0, 0, 0, 0, 0, // Padding // NOLINT
                0, 0, 0, 0, 0, 0, 0, 0, // NOLINT
                0, 0, 0, 0, 0, 0, 0, 0, // NOLINT
                0, 0, 0, 0, 0, 0, 0, 0, // NOLINT
                0, 0, 0, 0, 0, 0, 0, 0, // NOLINT
                0, 0, 0, 0, 0, 0, 0, 0, // NOLINT
                0, 0, 0, 0, 0, 0, 0, 0, // NOLINT
                0, 0, 0, 0, 0, 0, 0, 0, // NOLINT
                0, 0, 0, 0, 0, 0, 0, 0, // NOLINT
                0, 0, 0, 0, 0, 0, 0, 0, // NOLINT
                0, 0, 0, 0, 0, 0, 0, 0, // NOLINT
                0, 0, 0, 0, 0, 0, 0, 0, // NOLINT
                0, 0, 0, 0, 0, 0, 0, 0, // NOLINT
                0, 0, 0, 0, 0, 0, 0, 0, // NOLINT
                0, 0, 0, 0, 0, 0, 0, 0, // NOLINT
                0, 0, 0, 0, 0, 0, 0, 0, // NOLINT
                0, 0, 0, 0, 0, 0, 0, 0, // NOLINT
                0, 0, 0, 0, 0, 0, 0, 0, // NOLINT
                0, 0, 0, 0, 0, 0, 0, 0, // NOLINT
                0, 0, 0, 0, 0, 0, 0, 0, // NOLINT
                0, 0, 0, 0, 0, 0, 0, 0  // NOLINT
            },
            zero);

    libsnark::block_variable<FieldT> input(
        pb, {pb_var_input}, "blake2s_block_input");

    // default chaining value
    libsnark::pb_variable_array<FieldT> pb_var_h =
        variable_array_from_bit_vector(
            {
                0, 1, 1, 0, 1, 0, 1, 1, // NOLINT
                0, 0, 0, 0, 1, 0, 0, 0, // NOLINT
                1, 1, 1, 0, 0, 1, 1, 0, // NOLINT
                0, 1, 0, 0, 0, 1, 1, 1, // NOLINT
                1, 0, 1, 1, 1, 0, 1, 1, // NOLINT
                0, 1, 1, 0, 0, 1, 1, 1, // NOLINT
                1, 0, 1, 0, 1, 1, 1, 0, // NOLINT
                1, 0, 0, 0, 0, 1, 0, 1, // NOLINT
                0, 0, 1, 1, 1, 1, 0, 0, // NOLINT
                0, 1, 1, 0, 1, 1, 1, 0, // NOLINT
                1, 1, 1, 1, 0, 0, 1, 1, // NOLINT
                0, 1, 1, 1, 0, 0, 1, 0, // NOLINT
                1, 0, 1, 0, 0, 1, 0, 1, // NOLINT
                0, 1, 0, 0, 1, 1, 1, 1, // NOLINT
                1, 1, 1, 1, 0, 1, 0, 1, // NOLINT
                0, 0, 1, 1, 1, 0, 1, 0, // NOLINT
                0, 1, 0, 1, 0, 0, 0, 1, // NOLINT
                0, 0, 0, 0, 1, 1, 1, 0, // NOLINT
                0, 1, 0, 1, 0, 0, 1, 0, // NOLINT
                0, 1, 1, 1, 1, 1, 1, 1, // NOLINT
                1, 0, 0, 1, 1, 0, 1, 1, // NOLINT
                0, 0, 0, 0, 0, 1, 0, 1, // NOLINT
                0, 1, 1, 0, 1, 0, 0, 0, // NOLINT
                1, 0, 0, 0, 1, 1, 0, 0, // NOLINT
                0, 0, 0, 1, 1, 1, 1, 1, // NOLINT
                1, 0, 0, 0, 0, 0, 1, 1, // NOLINT
                1, 1, 0, 1, 1, 0, 0, 1, // NOLINT
                1, 0, 1, 0, 1, 0, 1, 1, // NOLINT
                0, 1, 0, 1, 1, 0, 1, 1, // NOLINT
                1, 1, 1, 0, 0, 0, 0, 0, // NOLINT
                1, 1, 0, 0, 1, 1, 0, 1, // NOLINT
                0, 0, 0, 1, 1, 0, 0, 1  // NOLINT
            },
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
                1, 0, 0, 1, 1, 0, 1, 0, // 9A // NOLINT
                1, 1, 1, 0, 1, 1, 0, 0, // EC // NOLINT
                0, 1, 1, 0, 1, 0, 0, 0, // 68 // NOLINT
                0, 0, 0, 0, 0, 1, 1, 0, // 06 // NOLINT
                0, 1, 1, 1, 1, 0, 0, 1, // 79 // NOLINT
                0, 1, 0, 0, 0, 1, 0, 1, // 45 // NOLINT
                0, 1, 1, 0, 0, 0, 0, 1, // 61 // NOLINT
                0, 0, 0, 1, 0, 0, 0, 0, // 10 // NOLINT
                0, 1, 1, 1, 1, 1, 1, 0, // 7E // NOLINT
                0, 1, 0, 1, 1, 0, 0, 1, // 59 // NOLINT
                0, 1, 0, 0, 1, 0, 1, 1, // 4B // NOLINT
                0, 0, 0, 1, 1, 1, 1, 1, // 1F // NOLINT
                0, 1, 1, 0, 1, 0, 1, 0, // 6A // NOLINT
                1, 0, 0, 0, 1, 0, 1, 0, // 8A // NOLINT
                0, 1, 1, 0, 1, 0, 1, 1, // 6B // NOLINT
                0, 0, 0, 0, 1, 1, 0, 0, // 0C // NOLINT
                1, 0, 0, 1, 0, 0, 1, 0, // 92 // NOLINT
                1, 0, 1, 0, 0, 0, 0, 0, // A0 // NOLINT
                1, 1, 0, 0, 1, 0, 1, 1, // CB // NOLINT
                1, 0, 1, 0, 1, 0, 0, 1, // A9 // NOLINT
                1, 0, 1, 0, 1, 1, 0, 0, // AC // NOLINT
                1, 1, 1, 1, 0, 1, 0, 1, // F5 // NOLINT
                1, 1, 1, 0, 0, 1, 0, 1, // E5 // NOLINT
                1, 1, 1, 0, 1, 0, 0, 1, // E9 // NOLINT
                0, 0, 1, 1, 1, 1, 0, 0, // 3C // NOLINT
                1, 1, 0, 0, 1, 0, 1, 0, // CA // NOLINT
                0, 0, 0, 0, 0, 1, 1, 0, // 06 // NOLINT
                1, 1, 1, 1, 0, 1, 1, 1, // F7 // NOLINT
                1, 0, 0, 0, 0, 0, 0, 1, // 81 // NOLINT
                1, 0, 0, 0, 0, 0, 0, 1, // 81 // NOLINT
                0, 0, 1, 1, 1, 0, 1, 1, // 3B // NOLINT
                0, 0, 0, 0, 1, 0, 1, 1  // 0B // NOLINT
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
                0, 1, 1, 0, 1, 0, 0, 0, // 68 // NOLINT
                0, 1, 1, 0, 0, 1, 0, 1, // 65 // NOLINT
                0, 1, 1, 0, 1, 1, 0, 0, // 6C // NOLINT
                0, 1, 1, 0, 1, 1, 0, 0, // 6C // NOLINT
                0, 1, 1, 0, 1, 1, 1, 1, // 6F // NOLINT
                0, 0, 1, 0, 0, 0, 0, 0, // 20 // NOLINT
                0, 1, 1, 1, 0, 1, 1, 1, // 77 // NOLINT
                0, 1, 1, 0, 1, 1, 1, 1, // 6F // NOLINT
                0, 1, 1, 1, 0, 0, 1, 0, // 72 // NOLINT
                0, 1, 1, 0, 1, 1, 0, 0, // 6C // NOLINT
                0, 1, 1, 0, 0, 1, 0, 0  // 64 // NOLINT
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
                1, 0, 0, 1, 1, 0, 1, 0, // 9A // NOLINT
                1, 1, 1, 0, 1, 1, 0, 0, // EC // NOLINT
                0, 1, 1, 0, 1, 0, 0, 0, // 68 // NOLINT
                0, 0, 0, 0, 0, 1, 1, 0, // 06 // NOLINT
                0, 1, 1, 1, 1, 0, 0, 1, // 79 // NOLINT
                0, 1, 0, 0, 0, 1, 0, 1, // 45 // NOLINT
                0, 1, 1, 0, 0, 0, 0, 1, // 61 // NOLINT
                0, 0, 0, 1, 0, 0, 0, 0, // 10 // NOLINT
                0, 1, 1, 1, 1, 1, 1, 0, // 7E // NOLINT
                0, 1, 0, 1, 1, 0, 0, 1, // 59 // NOLINT
                0, 1, 0, 0, 1, 0, 1, 1, // 4B // NOLINT
                0, 0, 0, 1, 1, 1, 1, 1, // 1F // NOLINT
                0, 1, 1, 0, 1, 0, 1, 0, // 6A // NOLINT
                1, 0, 0, 0, 1, 0, 1, 0, // 8A // NOLINT
                0, 1, 1, 0, 1, 0, 1, 1, // 6B // NOLINT
                0, 0, 0, 0, 1, 1, 0, 0, // 0C // NOLINT
                1, 0, 0, 1, 0, 0, 1, 0, // 92 // NOLINT
                1, 0, 1, 0, 0, 0, 0, 0, // A0 // NOLINT
                1, 1, 0, 0, 1, 0, 1, 1, // CB // NOLINT
                1, 0, 1, 0, 1, 0, 0, 1, // A9 // NOLINT
                1, 0, 1, 0, 1, 1, 0, 0, // AC // NOLINT
                1, 1, 1, 1, 0, 1, 0, 1, // F5 // NOLINT
                1, 1, 1, 0, 0, 1, 0, 1, // E5 // NOLINT
                1, 1, 1, 0, 1, 0, 0, 1, // E9 // NOLINT
                0, 0, 1, 1, 1, 1, 0, 0, // 3C // NOLINT
                1, 1, 0, 0, 1, 0, 1, 0, // CA // NOLINT
                0, 0, 0, 0, 0, 1, 1, 0, // 06 // NOLINT
                1, 1, 1, 1, 0, 1, 1, 1, // F7 // NOLINT
                1, 0, 0, 0, 0, 0, 0, 1, // 81 // NOLINT
                1, 0, 0, 0, 0, 0, 0, 1, // 81 // NOLINT
                0, 0, 1, 1, 1, 0, 1, 1, // 3B // NOLINT
                0, 0, 0, 0, 1, 0, 1, 1  // 0B // NOLINT
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
                0, 1, 1, 1, 1, 0, 1, 0, // 7A // NOLINT
                0, 1, 1, 0, 0, 1, 0, 1, // 65 // NOLINT
                0, 1, 1, 1, 0, 1, 0, 0, // 74 // NOLINT
                0, 1, 1, 0, 1, 0, 0, 0, // 68 // NOLINT
                0, 1, 1, 1, 1, 0, 1, 0, // 7A // NOLINT
                0, 1, 1, 0, 0, 1, 0, 1, // 65 // NOLINT
                0, 1, 1, 1, 0, 1, 0, 0, // 74 // NOLINT
                0, 1, 1, 0, 1, 0, 0, 0, // 68 // NOLINT
                0, 1, 1, 1, 1, 0, 1, 0, // 7A // NOLINT
                0, 1, 1, 0, 0, 1, 0, 1, // 65 // NOLINT
                0, 1, 1, 1, 0, 1, 0, 0, // 74 // NOLINT
                0, 1, 1, 0, 1, 0, 0, 0, // 68 // NOLINT
                0, 1, 1, 1, 1, 0, 1, 0, // 7A // NOLINT
                0, 1, 1, 0, 0, 1, 0, 1, // 65 // NOLINT
                0, 1, 1, 1, 0, 1, 0, 0, // 74 // NOLINT
                0, 1, 1, 0, 1, 0, 0, 0, // 68 // NOLINT
                0, 1, 1, 1, 1, 0, 1, 0, // 7A // NOLINT
                0, 1, 1, 0, 0, 1, 0, 1, // 65 // NOLINT
                0, 1, 1, 1, 0, 1, 0, 0, // 74 // NOLINT
                0, 1, 1, 0, 1, 0, 0, 0, // 68 // NOLINT
                0, 1, 1, 1, 1, 0, 1, 0, // 7A // NOLINT
                0, 1, 1, 0, 0, 1, 0, 1, // 65 // NOLINT
                0, 1, 1, 1, 0, 1, 0, 0, // 74 // NOLINT
                0, 1, 1, 0, 1, 0, 0, 0, // 68 // NOLINT
                0, 1, 1, 1, 1, 0, 1, 0, // 7A // NOLINT
                0, 1, 1, 0, 0, 1, 0, 1, // 65 // NOLINT
                0, 1, 1, 1, 0, 1, 0, 0, // 74 // NOLINT
                0, 1, 1, 0, 1, 0, 0, 0, // 68 // NOLINT
                0, 1, 1, 1, 1, 0, 1, 0, // 7A // NOLINT
                0, 1, 1, 0, 0, 1, 0, 1, // 65 // NOLINT
                0, 1, 1, 1, 0, 1, 0, 0, // 74 // NOLINT
                0, 1, 1, 0, 1, 0, 0, 0, // 68 // NOLINT
                0, 1, 1, 1, 1, 0, 1, 0, // 7A // NOLINT
                0, 1, 1, 0, 0, 1, 0, 1, // 65 // NOLINT
                0, 1, 1, 1, 0, 1, 0, 0, // 74 // NOLINT
                0, 1, 1, 0, 1, 0, 0, 0, // 68 // NOLINT
                0, 1, 1, 1, 1, 0, 1, 0, // 7A // NOLINT
                0, 1, 1, 0, 0, 1, 0, 1, // 65 // NOLINT
                0, 1, 1, 1, 0, 1, 0, 0, // 74 // NOLINT
                0, 1, 1, 0, 1, 0, 0, 0, // 68 // NOLINT
                0, 1, 1, 1, 1, 0, 1, 0, // 7A // NOLINT
                0, 1, 1, 0, 0, 1, 0, 1, // 65 // NOLINT
                0, 1, 1, 1, 0, 1, 0, 0, // 74 // NOLINT
                0, 1, 1, 0, 1, 0, 0, 0, // 68 // NOLINT
                0, 1, 1, 1, 1, 0, 1, 0, // 7A // NOLINT
                0, 1, 1, 0, 0, 1, 0, 1, // 65 // NOLINT
                0, 1, 1, 1, 0, 1, 0, 0, // 74 // NOLINT
                0, 1, 1, 0, 1, 0, 0, 0, // 68 // NOLINT
                0, 1, 1, 1, 1, 0, 1, 0, // 7A // NOLINT
                0, 1, 1, 0, 0, 1, 0, 1, // 65 // NOLINT
                0, 1, 1, 1, 0, 1, 0, 0, // 74 // NOLINT
                0, 1, 1, 0, 1, 0, 0, 0, // 68 // NOLINT
                0, 1, 1, 1, 1, 0, 1, 0, // 7A // NOLINT
                0, 1, 1, 0, 0, 1, 0, 1, // 65 // NOLINT
                0, 1, 1, 1, 0, 1, 0, 0, // 74 // NOLINT
                0, 1, 1, 0, 1, 0, 0, 0, // 68 // NOLINT
                0, 1, 1, 1, 1, 0, 1, 0, // 7A // NOLINT
                0, 1, 1, 0, 0, 1, 0, 1, // 65 // NOLINT
                0, 1, 1, 1, 0, 1, 0, 0, // 74 // NOLINT
                0, 1, 1, 0, 1, 0, 0, 0, // 68 // NOLINT
                0, 1, 1, 1, 1, 0, 1, 0, // 7A // NOLINT
                0, 1, 1, 0, 0, 1, 0, 1, // 65 // NOLINT
                0, 1, 1, 1, 0, 1, 0, 0, // 74 // NOLINT
                0, 1, 1, 0, 1, 0, 0, 0, // 68 // NOLINT
                0, 1, 1, 1, 1, 0, 1, 0, // 7A // NOLINT
                0, 1, 1, 0, 0, 1, 0, 1, // 65 // NOLINT
                0, 1, 1, 1, 0, 1, 0, 0, // 74 // NOLINT
                0, 1, 1, 0, 1, 0, 0, 0, // 68 // NOLINT
                0, 1, 1, 1, 1, 0, 1, 0, // 7A // NOLINT
                0, 1, 1, 0, 0, 1, 0, 1, // 65 // NOLINT
                0, 1, 1, 1, 0, 1, 0, 0, // 74 // NOLINT
                0, 1, 1, 0, 1, 0, 0, 0, // 68 // NOLINT
                0, 1, 1, 1, 1, 0, 1, 0, // 7A // NOLINT
                0, 1, 1, 0, 0, 1, 0, 1, // 65 // NOLINT
                0, 1, 1, 1, 0, 1, 0, 0, // 74 // NOLINT
                0, 1, 1, 0, 1, 0, 0, 0, // 68 // NOLINT
                0, 1, 1, 1, 1, 0, 1, 0, // 7A // NOLINT
                0, 1, 1, 0, 0, 1, 0, 1, // 65 // NOLINT
                0, 1, 1, 1, 0, 1, 0, 0, // 74 // NOLINT
                0, 1, 1, 0, 1, 0, 0, 0, // 68 // NOLINT
                0, 1, 1, 1, 1, 0, 1, 0, // 7A // NOLINT
                0, 1, 1, 0, 0, 1, 0, 1, // 65 // NOLINT
                0, 1, 1, 1, 0, 1, 0, 0, // 74 // NOLINT
                0, 1, 1, 0, 1, 0, 0, 0, // 68 // NOLINT
                0, 1, 1, 1, 1, 0, 1, 0, // 7A // NOLINT
                0, 1, 1, 0, 0, 1, 0, 1, // 65 // NOLINT
                0, 1, 1, 1, 0, 1, 0, 0, // 74 // NOLINT
                0, 1, 1, 0, 1, 0, 0, 0, // 68 // NOLINT
                0, 1, 1, 1, 1, 0, 1, 0, // 7A // NOLINT
                0, 1, 1, 0, 0, 1, 0, 1, // 65 // NOLINT
                0, 1, 1, 1, 0, 1, 0, 0, // 74 // NOLINT
                0, 1, 1, 0, 1, 0, 0, 0, // 68 // NOLINT
                0, 1, 1, 1, 1, 0, 1, 0, // 7A // NOLINT
                0, 1, 1, 0, 0, 1, 0, 1, // 65 // NOLINT
                0, 1, 1, 1, 0, 1, 0, 0, // 74 // NOLINT
                0, 1, 1, 0, 1, 0, 0, 0, // 68 // NOLINT
                0, 1, 1, 1, 1, 0, 1, 0, // 7A // NOLINT
                0, 1, 1, 0, 0, 1, 0, 1, // 65 // NOLINT
                0, 1, 1, 1, 0, 1, 0, 0, // 74 // NOLINT
                0, 1, 1, 0, 1, 0, 0, 0, // 68 // NOLINT
                0, 1, 1, 1, 1, 0, 1, 0, // 7A // NOLINT
                0, 1, 1, 0, 0, 1, 0, 1, // 65 // NOLINT
                0, 1, 1, 1, 0, 1, 0, 0, // 74 // NOLINT
                0, 1, 1, 0, 1, 0, 0, 0, // 68 // NOLINT
                0, 1, 1, 1, 1, 0, 1, 0, // 7A // NOLINT
                0, 1, 1, 0, 0, 1, 0, 1, // 65 // NOLINT
                0, 1, 1, 1, 0, 1, 0, 0, // 74 // NOLINT
                0, 1, 1, 0, 1, 0, 0, 0, // 68 // NOLINT
                0, 1, 1, 1, 1, 0, 1, 0, // 7A // NOLINT
                0, 1, 1, 0, 0, 1, 0, 1, // 65 // NOLINT
                0, 1, 1, 1, 0, 1, 0, 0, // 74 // NOLINT
                0, 1, 1, 0, 1, 0, 0, 0, // 68 // NOLINT
                0, 1, 1, 1, 1, 0, 1, 0, // 7A // NOLINT
                0, 1, 1, 0, 0, 1, 0, 1, // 65 // NOLINT
                0, 1, 1, 1, 0, 1, 0, 0, // 74 // NOLINT
                0, 1, 1, 0, 1, 0, 0, 0, // 68 // NOLINT
                0, 1, 1, 1, 1, 0, 1, 0, // 7A // NOLINT
                0, 1, 1, 0, 0, 1, 0, 1, // 65 // NOLINT
                0, 1, 1, 1, 0, 1, 0, 0, // 74 // NOLINT
                0, 1, 1, 0, 1, 0, 0, 0, // 68 // NOLINT
                0, 1, 1, 1, 1, 0, 1, 0, // 7A // NOLINT
                0, 1, 1, 0, 0, 1, 0, 1, // 65 // NOLINT
                0, 1, 1, 1, 0, 1, 0, 0, // 74 // NOLINT
                0, 1, 1, 0, 1, 0, 0, 0, // 68 // NOLINT
                0, 1, 1, 1, 1, 0, 1, 0, // 7A // NOLINT
                0, 1, 1, 0, 0, 1, 0, 1, // 65 // NOLINT
                0, 1, 1, 1, 0, 1, 0, 0, // 74 // NOLINT
                0, 1, 1, 0, 1, 0, 0, 0  // 68 // NOLINT
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
