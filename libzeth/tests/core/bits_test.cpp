// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/core/bits.hpp"

#include <gtest/gtest.h>

using namespace libzeth;

TEST(BitsTest, Bits32)
{
    const bits32 a{
        true,  false, true,  false, true,  true,  true,  false,
        true,  false, true,  false, true,  false, true,  false,
        false, true,  false, true,  false, false, false, true,
        false, true,  false, true,  false, true,  false, true,
    };
    const std::vector<bool> expect{
        true,  false, true,  false, true,  true,  true,  false,
        true,  false, true,  false, true,  false, true,  false,
        false, true,  false, true,  false, false, false, true,
        false, true,  false, true,  false, true,  false, true,
    };
    ASSERT_EQ(expect, bits32_to_vector(a));
}

TEST(BitsTest, Bits64)
{
    const bits64 a{
        false, false, false, false, false, false, false, true,  false, false,
        true,  false, false, false, true,  true,  false, true,  false, false,
        false, true,  false, true,  false, true,  true,  false, false, true,
        true,  true,  true,  false, false, false, true,  false, false, true,
        true,  false, true,  false, true,  false, true,  true,  true,  true,
        false, false, true,  true,  false, true,  true,  true,  true,  false,
        true,  true,  true,  true,
    };
    const std::vector<bool> expect{
        false, false, false, false, false, false, false, true,  false, false,
        true,  false, false, false, true,  true,  false, true,  false, false,
        false, true,  false, true,  false, true,  true,  false, false, true,
        true,  true,  true,  false, false, false, true,  false, false, true,
        true,  false, true,  false, true,  false, true,  true,  true,  true,
        false, false, true,  true,  false, true,  true,  true,  true,  false,
        true,  true,  true,  true,
    };
    const std::string expect_hex = "0123456789abcdef";

    const std::vector<bool> a_vector = bits64_to_vector(a);
    const bits64 aa = bits64_from_vector(a_vector);
    const bits64 a_from_hex = bits64_from_hex(expect_hex);

    ASSERT_EQ(expect, a_vector);
    ASSERT_EQ(a, aa);
    ASSERT_EQ(a_from_hex, a);
}

// TODO: Tests for bits256

// TODO: Tests for bits384

// TODO: Tests for bits_addr

TEST(BitsTest, BitVectorFromSizeT)
{
    const std::vector<bool> expect_le_a7 = {
        true, true, true, false, false, true, false, true};
    const std::vector<bool> expect_le_72 = {
        false, true, false, false, true, true, true};
    const std::vector<bool> expect_be_100 = {
        true, false, false, false, false, false, false, false, false};
    const std::vector<bool> expect_be_a5 = {
        true, false, true, false, false, true, false, true};
    const std::vector<bool> expect_be_40000005a = {
        true,  false, false,                                    // 4
        false, false, false, false, false, false, false, false, // 00
        false, false, false, false, false, false, false, false, // 00
        false, false, false, false, false, false, false, false, // 00
        false, true,  false, true,  true,  false, true,  false, // 5a
    };

    const std::vector<bool> le_a7 = bit_vector_from_size_t_le(0xa7);
    const std::vector<bool> le_72 = bit_vector_from_size_t_le(0x72);
    const std::vector<bool> be_a5 = bit_vector_from_size_t_be(0xa5);
    const std::vector<bool> be_100 = bit_vector_from_size_t_be(0x100);
    const std::vector<bool> be_40000005a =
        bit_vector_from_size_t_be(0x40000005aull);

    ASSERT_EQ(expect_le_a7, le_a7);
    ASSERT_EQ(expect_le_72, le_72);
    ASSERT_EQ(expect_be_100, be_100);
    ASSERT_EQ(expect_be_a5, be_a5);
    ASSERT_EQ(expect_be_40000005a, be_40000005a);
}

TEST(BitsTest, BitVectorFromHex)
{
    const std::vector<bool> expect_hex_72 = {
        false, true, true, true, false, false, true, false};
    const std::vector<bool> expect_hex_56ab = {false,
                                               true,
                                               false,
                                               true,
                                               false,
                                               true,
                                               true,
                                               false,
                                               true,
                                               false,
                                               true,
                                               false,
                                               true,
                                               false,
                                               true,
                                               true};
    const std::vector<bool> hex_72 = bit_vector_from_hex("72");
    const std::vector<bool> hex_56ab = bit_vector_from_hex("56ab");

    ASSERT_EQ(expect_hex_72, hex_72);
    ASSERT_EQ(expect_hex_56ab, hex_56ab);
}

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
