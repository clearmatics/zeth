// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/core/bits.hpp"

#include <gtest/gtest.h>

using namespace libzeth;

TEST(TestBits, Bits32)
{
    const bits32 a{
        1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,
        0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
    };
    const std::vector<bool> expect{
        1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,
        0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
    };
    ASSERT_EQ(expect, bits32_to_vector(a));
}

TEST(TestBits, Bits64)
{
    const bits64 a{
        0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1,
        0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0,
        1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1,
    };
    const std::vector<bool> expect{
        0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1,
        0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0,
        1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1,
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

// TODO: Tests for bit_vector

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
