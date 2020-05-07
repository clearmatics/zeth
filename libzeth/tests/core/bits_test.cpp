// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/core/bits.hpp"

#include <gtest/gtest.h>

using namespace libzeth;

TEST(BitsTest, Bits32)
{
    const bits32 a{
        1, 0, 1, 0, 1, 1, 1, 0, // NOLINT
        1, 0, 1, 0, 1, 0, 1, 0, // NOLINT
        0, 1, 0, 1, 0, 0, 0, 1, // NOLINT
        0, 1, 0, 1, 0, 1, 0, 1, // NOLINT
    };
    const std::vector<bool> expect{
        1, 0, 1, 0, 1, 1, 1, 0, // NOLINT
        1, 0, 1, 0, 1, 0, 1, 0, // NOLINT
        0, 1, 0, 1, 0, 0, 0, 1, // NOLINT
        0, 1, 0, 1, 0, 1, 0, 1, // NOLINT
    };
    ASSERT_EQ(expect, bits32_to_vector(a));
}

TEST(BitsTest, Bits64)
{
    const bits64 a{
        0, 0, 0, 0, 0, 0, 0, 1, // NOLINT
        0, 0, 1, 0, 0, 0, 1, 1, // NOLINT
        0, 1, 0, 0, 0, 1, 0, 1, // NOLINT
        0, 1, 1, 0, 0, 1, 1, 1, // NOLINT
        1, 0, 0, 0, 1, 0, 0, 1, // NOLINT
        1, 0, 1, 0, 1, 0, 1, 1, // NOLINT
        1, 1, 0, 0, 1, 1, 0, 1, // NOLINT
        1, 1, 1, 0, 1, 1, 1, 1, // NOLINT
    };
    const std::vector<bool> expect{
        0, 0, 0, 0, 0, 0, 0, 1, // NOLINT
        0, 0, 1, 0, 0, 0, 1, 1, // NOLINT
        0, 1, 0, 0, 0, 1, 0, 1, // NOLINT
        0, 1, 1, 0, 0, 1, 1, 1, // NOLINT
        1, 0, 0, 0, 1, 0, 0, 1, // NOLINT
        1, 0, 1, 0, 1, 0, 1, 1, // NOLINT
        1, 1, 0, 0, 1, 1, 0, 1, // NOLINT
        1, 1, 1, 0, 1, 1, 1, 1, // NOLINT
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
    // NOLINTNEXTLINE(readability-implicit-bool-conversion)
    const std::vector<bool> expect_le_a7 = {1, 1, 1, 0, 0, 1, 0, 1};
    // NOLINTNEXTLINE(readability-implicit-bool-conversion)
    const std::vector<bool> expect_le_72 = {0, 1, 0, 0, 1, 1, 1};
    // NOLINTNEXTLINE(readability-implicit-bool-conversion)
    const std::vector<bool> expect_be_100 = {1, 0, 0, 0, 0, 0, 0, 0, 0};
    // NOLINTNEXTLINE(readability-implicit-bool-conversion)
    const std::vector<bool> expect_be_a5 = {1, 0, 1, 0, 0, 1, 0, 1};
    const std::vector<bool> expect_be_40000005a = {
        1, 0, 0,                // 4  // NOLINT
        0, 0, 0, 0, 0, 0, 0, 0, // 00 // NOLINT
        0, 0, 0, 0, 0, 0, 0, 0, // 00 // NOLINT
        0, 0, 0, 0, 0, 0, 0, 0, // 00 // NOLINT
        0, 1, 0, 1, 1, 0, 1, 0, // 5a // NOLINT
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
    // NOLINTNEXTLINE(readability-implicit-bool-conversion)
    const std::vector<bool> expect_hex_72 = {0, 1, 1, 1, 0, 0, 1, 0};
    const std::vector<bool> expect_hex_56ab = {
        0,
        1,
        0,
        1,
        0,
        1,
        1,
        0, // NOLINT
        1,
        0,
        1,
        0,
        1,
        0,
        1,
        1 // NOLINT
    };
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
