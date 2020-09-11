// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/core/bits.hpp"

#include <gtest/gtest.h>

using namespace libzeth;

// Ensure we are testing multiple words, and partial words.
static const size_t TEST_NUM_BITS = 72;
static const size_t TEST_NUM_HEX_CHARS = TEST_NUM_BITS / 4;
using bits_t = bits<TEST_NUM_BITS>;

TEST(BitsTest, InitializedAsZero)
{
    const bits_t x;
    ASSERT_TRUE(x.is_zero());
}

TEST(BitsTest, FromHexFromInitializerLIst)
{
    const std::string expect_x_hex = "79f2e5cb972f5ebc79";
    const bits_t x{
        0, 1, 1, 1, 1, 0, 0, 1, // 79
        1, 1, 1, 1, 0, 0, 1, 0, // f2
        1, 1, 1, 0, 0, 1, 0, 1, // e5
        1, 1, 0, 0, 1, 0, 1, 1, // cb
        1, 0, 0, 1, 0, 1, 1, 1, // 97
        0, 0, 1, 0, 1, 1, 1, 1, // 2f
        0, 1, 0, 1, 1, 1, 1, 0, // 5e
        1, 0, 1, 1, 1, 1, 0, 0, // bc
        0, 1, 1, 1, 1, 0, 0, 1, // 79
    };
    ASSERT_EQ(bits_t::from_hex(expect_x_hex), x);
}

TEST(BitsTest, FromInvalidHex)
{
    // Too long
    ASSERT_THROW(
        bits_t::from_hex("abdcef0123456789abcd"), std::invalid_argument);
    // Too short
    ASSERT_THROW(bits_t::from_hex("abdcef0123456789"), std::invalid_argument);
}

TEST(BitsTest, FromVectorToVector)
{
    const std::string expect_x_hex = "79f2e5cb972f5dbc79";
    const std::vector<bool> expect_x_vector{
        0, 1, 1, 1, 1, 0, 0, 1, // 79
        1, 1, 1, 1, 0, 0, 1, 0, // f2
        1, 1, 1, 0, 0, 1, 0, 1, // e5
        1, 1, 0, 0, 1, 0, 1, 1, // cb
        1, 0, 0, 1, 0, 1, 1, 1, // 97
        0, 0, 1, 0, 1, 1, 1, 1, // 2f
        0, 1, 0, 1, 1, 1, 1, 0, // 5d
        1, 0, 1, 1, 1, 1, 0, 0, // bc
        0, 1, 1, 1, 1, 0, 0, 1, // 79
    };
    const bits_t x = bits_t::from_vector(expect_x_vector);
    const std::vector<bool> x_vector = x.to_vector();

    for (size_t i = 0; i < TEST_NUM_BITS; ++i) {
        ASSERT_EQ(expect_x_vector[i], x_vector[i]);
    }

    ASSERT_FALSE(x.is_zero());
    ASSERT_EQ(expect_x_vector.size(), x_vector.size());
    ASSERT_EQ(expect_x_vector, x_vector);
}

TEST(BitsTest, EqualityInequalityZero)
{
    const std::string x_hex = "79f2e5cb972f5dbc79";
    const std::string y_hex = "abcdef0123456789ab";

    const bits_t x = bits_t::from_hex(x_hex);
    const bits_t x_2 = bits_t::from_hex(x_hex);
    const bits_t y = bits_t::from_hex(y_hex);

    ASSERT_TRUE(x == x_2);
    ASSERT_TRUE(x != y);
    ASSERT_FALSE(x.is_zero());
    ASSERT_TRUE(
        bits_t::from_hex(std::string(TEST_NUM_HEX_CHARS, '0')).is_zero());
}

TEST(BitsTest, Xor)
{
    const std::string x_hex = "79f2e5cb972f5dbc79";
    const std::string y_hex = "abdcef0123456789ab";
    const std::string x_xor_y_hex = "d22e0acab46a3a35d2";

    const bits_t x = bits_t::from_hex(x_hex);
    const bits_t y = bits_t::from_hex(y_hex);
    const bits_t x_xor_y = bits_xor(x, y);

    ASSERT_EQ(bits_t::from_hex(x_xor_y_hex), x_xor_y);
}

TEST(BitsTest, AddCarry)
{
    const std::string x_hex = "79f2e5cb972f5dbc79";
    const std::string y_hex = "abdcef0123456789ab";
    const std::string z_hex = "2abdcef0123456789a";
    const std::string x_add_y_hex = "25cfd4ccba74c54624";
    const std::string x_add_z_hex = "a4b0b4bba963b43513";

    const bits_t x = bits_t::from_hex(x_hex);
    const bits_t y = bits_t::from_hex(y_hex);
    const bits_t z = bits_t::from_hex(z_hex);
    const bits_t x_add_y = bits_add(x, y);
    const bits_t x_add_z = bits_add(x, z, true);

    ASSERT_EQ(bits_t::from_hex(x_add_y_hex), x_add_y);
    ASSERT_EQ(bits_t::from_hex(x_add_z_hex), x_add_z);
    ASSERT_THROW(bits_add(x, y, true), std::overflow_error);
}

TEST(BitsTest, BitVectorFromSizeT)
{
    const std::vector<bool> expect_le_a7 = {1, 1, 1, 0, 0, 1, 0, 1};
    const std::vector<bool> expect_le_72 = {0, 1, 0, 0, 1, 1, 1};
    const std::vector<bool> expect_be_100 = {1, 0, 0, 0, 0, 0, 0, 0, 0};
    const std::vector<bool> expect_be_a5 = {1, 0, 1, 0, 0, 1, 0, 1};
    const std::vector<bool> expect_be_40000005a = {
        1, 0, 0,                // 4
        0, 0, 0, 0, 0, 0, 0, 0, // 00
        0, 0, 0, 0, 0, 0, 0, 0, // 00
        0, 0, 0, 0, 0, 0, 0, 0, // 00
        0, 1, 0, 1, 1, 0, 1, 0, // 5a
    };

    const std::vector<bool> le_a7 = bit_vector_from_size_t_le(0xa7);
    const std::vector<bool> le_72 = bit_vector_from_size_t_le(0x72);
    const std::vector<bool> be_a5 = bit_vector_from_size_t_be(0xa5);
    const std::vector<bool> be_100 = bit_vector_from_size_t_be(0x100);
    const std::vector<bool> be_40000005a =
        bit_vector_from_size_t_be(0x40000005aULL);

    ASSERT_EQ(expect_le_a7, le_a7);
    ASSERT_EQ(expect_le_72, le_72);
    ASSERT_EQ(expect_be_100, be_100);
    ASSERT_EQ(expect_be_a5, be_a5);
    ASSERT_EQ(expect_be_40000005a, be_40000005a);
}

TEST(BitsTest, BitVectorFromHex)
{
    const std::vector<bool> expect_hex_72 = {0, 1, 1, 1, 0, 0, 1, 0};
    const std::vector<bool> expect_hex_56ab = {
        0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1};
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
