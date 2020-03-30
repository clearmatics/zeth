// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/circuits/blake2s/blake2s_comp.hpp"
#include "libzeth/circuits/blake2s/g_primitive.hpp"
#include "libzeth/snarks_alias.hpp"

#include "gtest/gtest.h"
#include <libff/common/default_types/ec_pp.hpp>

// Access the `from_bits` function and other utils
#include "libzeth/circuits/circuits_utils.hpp"
#include "libzeth/util.hpp"

using namespace libsnark;
using namespace libzeth;

typedef libff::default_ec_pp ppT;
typedef libff::Fr<ppT> FieldT;

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

    libsnark::pb_variable<FieldT> ZERO;
    ZERO.allocate(pb, "zero");
    pb.val(ZERO) = FieldT::zero();

    libsnark::pb_variable_array<FieldT> a = from_bits(
        {
            0, 1, 1, 0, 1, 0, 1, 1, // 6B
            0, 0, 0, 0, 1, 0, 0, 0, // 08
            1, 1, 1, 0, 0, 1, 1, 0, // E6
            0, 1, 0, 0, 0, 1, 1, 1  // 47
        },
        ZERO);

    libsnark::pb_variable_array<FieldT> b = from_bits(
        {
            0, 1, 0, 1, 0, 0, 0, 1, // 51
            0, 0, 0, 0, 1, 1, 1, 0, // 0E
            0, 1, 0, 1, 0, 0, 1, 0, // 52
            0, 1, 1, 1, 1, 1, 1, 1  // 7F
        },
        ZERO);

    libsnark::pb_variable_array<FieldT> c = from_bits(
        {
            0, 1, 1, 0, 1, 0, 1, 0, // 6A
            0, 0, 0, 0, 1, 0, 0, 1, // 09
            1, 1, 1, 0, 0, 1, 1, 0, // E6
            0, 1, 1, 0, 0, 1, 1, 1  // 67
        },
        ZERO);

    libsnark::pb_variable_array<FieldT> d = from_bits(
        {
            0, 1, 0, 1, 0, 0, 0, 1, // 51
            0, 0, 0, 0, 1, 1, 1, 0, // 0E
            0, 1, 0, 1, 0, 0, 1, 0, // 52
            0, 1, 1, 1, 0, 1, 0, 0  // 74
        },
        ZERO);

    // First word in little endian "lleh"
    libsnark::pb_variable_array<FieldT> x = from_bits(
        {
            0, 1, 1, 0, 1, 1, 0, 0, // 6C
            0, 1, 1, 0, 1, 1, 0, 0, // 6C
            0, 1, 1, 0, 0, 1, 0, 1, // 65
            0, 1, 1, 0, 1, 0, 0, 0  // 68
        },
        ZERO);

    // Second word in little endian "ow o"
    libsnark::pb_variable_array<FieldT> y = from_bits(
        {
            0, 1, 1, 0, 1, 1, 1, 1, // 6F
            0, 1, 1, 1, 0, 1, 1, 1, // 77
            0, 0, 1, 0, 0, 0, 0, 0, // 20
            0, 1, 1, 0, 1, 1, 1, 1  // 6F
        },
        ZERO);

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

    libsnark::pb_variable_array<FieldT> a2_expected = from_bits(
        {
            0, 1, 1, 1, 0, 0, 0, 0, // 70
            1, 0, 1, 1, 0, 0, 0, 1, // B1
            0, 0, 1, 1, 0, 1, 0, 1, // 35
            0, 0, 1, 1, 1, 1, 0, 1  // 3D
        },
        ZERO);

    libsnark::pb_variable_array<FieldT> b2_expected = from_bits(
        {
            1, 1, 0, 0, 0, 0, 0, 0, // C0
            0, 1, 1, 1, 1, 1, 1, 1, // 7F
            0, 0, 1, 0, 1, 1, 1, 0, // 2E
            0, 1, 1, 1, 1, 0, 1, 1  // 7B
        },
        ZERO);

    libsnark::pb_variable_array<FieldT> c2_expected = from_bits(
        {
            1, 1, 1, 0, 0, 1, 1, 1, // E7
            0, 0, 1, 0, 0, 0, 0, 1, // 21
            0, 1, 0, 0, 1, 0, 1, 1, // 4B
            0, 1, 0, 0, 0, 0, 0, 0  // 40
        },
        ZERO);

    libsnark::pb_variable_array<FieldT> d2_expected = from_bits(
        {
            1, 0, 1, 1, 0, 0, 0, 0, // B0
            1, 0, 1, 1, 1, 1, 0, 0, // BC
            1, 1, 1, 0, 1, 0, 1, 1, // EB
            0, 1, 0, 0, 1, 1, 0, 0  // 4C
        },
        ZERO);

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

    libsnark::pb_variable<FieldT> ZERO;
    ZERO.allocate(pb, "zero");
    pb.val(ZERO) = FieldT::zero();

    // b"hello world" in big endian
    libsnark::pb_variable_array<FieldT> pb_va_input = from_bits(
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
        },
        ZERO);

    libsnark::block_variable<FieldT> input(
        pb, {pb_va_input}, "blake2s_block_input");

    libsnark::digest_variable<FieldT> output(pb, BLAKE2s_digest_size, "output");

    BLAKE2s_256_comp<FieldT> blake2s_comp_gadget(pb, input, output);
    blake2s_comp_gadget.generate_r1cs_constraints();
    blake2s_comp_gadget.generate_r1cs_witness();

    // blake2s(b"hello world")
    libsnark::pb_variable_array<FieldT> expected = from_bits(
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
        ZERO);

    ASSERT_EQ(expected.get_bits(pb), output.bits.get_bits(pb));
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
