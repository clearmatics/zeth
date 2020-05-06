// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/core/utils.hpp"

#include <gtest/gtest.h>

namespace
{

static const size_t DUMMY_BUFFER_SIZE = 16;

static const uint8_t dummy_bytes[DUMMY_BUFFER_SIZE] = {
    0x00,
    0x11,
    0x22,
    0x33,
    0x44,
    0x55,
    0x66,
    0x77, //
    0x88,
    0x99,
    0xaa,
    0xbb,
    0xcc,
    0xdd,
    0xee,
    0xff, //
};

static const std::string dummy_hex = "00112233445566778899aabbccddeeff";
static const std::string dummy_hex_prefixed =
    "0x00112233445566778899aabbccddeeff";
static const std::string dummy_hex_reversed =
    "ffeeddccbbaa99887766554433221100";
static const std::string dummy_hex_reversed_prefixed =
    "0xffeeddccbbaa99887766554433221100";

TEST(UtilsTest, HexToBytes)
{
    uint8_t buffer[DUMMY_BUFFER_SIZE];

    memset(buffer, 0xff, DUMMY_BUFFER_SIZE);
    libzeth::hex_to_bytes(dummy_hex, buffer, DUMMY_BUFFER_SIZE);
    ASSERT_EQ(0, memcmp(buffer, dummy_bytes, DUMMY_BUFFER_SIZE));

    memset(buffer, 0xff, DUMMY_BUFFER_SIZE);
    libzeth::hex_to_bytes(dummy_hex_prefixed, buffer, DUMMY_BUFFER_SIZE);
    ASSERT_EQ(0, memcmp(buffer, dummy_bytes, DUMMY_BUFFER_SIZE));

    memset(buffer, 0xff, DUMMY_BUFFER_SIZE);
    libzeth::hex_to_bytes_reversed(
        dummy_hex_reversed, buffer, DUMMY_BUFFER_SIZE);
    ASSERT_EQ(0, memcmp(buffer, dummy_bytes, DUMMY_BUFFER_SIZE));

    memset(buffer, 0xff, DUMMY_BUFFER_SIZE);
    libzeth::hex_to_bytes_reversed(
        dummy_hex_reversed_prefixed, buffer, DUMMY_BUFFER_SIZE);
    ASSERT_EQ(0, memcmp(buffer, dummy_bytes, DUMMY_BUFFER_SIZE));

    std::string bytes_str = libzeth::hex_to_bytes(dummy_hex);
    ASSERT_EQ(DUMMY_BUFFER_SIZE, bytes_str.size());
    ASSERT_EQ(0, memcmp(dummy_bytes, bytes_str.c_str(), DUMMY_BUFFER_SIZE));
}

TEST(UtilsTest, BytesToHex)
{
    ASSERT_EQ(dummy_hex, libzeth::bytes_to_hex(dummy_bytes, DUMMY_BUFFER_SIZE));

    ASSERT_EQ(
        dummy_hex_reversed,
        libzeth::bytes_to_hex_reversed(dummy_bytes, DUMMY_BUFFER_SIZE));
}

TEST(UtilsTest, HexToBytesInvalid)
{
    uint8_t buffer[2];
    // invalid length
    ASSERT_THROW(
        libzeth::hex_to_bytes("aaa", buffer, 2), std::invalid_argument);
    // char < '0'
    ASSERT_THROW(libzeth::hex_to_bytes(" f", buffer, 2), std::invalid_argument);
    // '9' < char < 'a'
    ASSERT_THROW(
        libzeth::hex_to_bytes("a:bb", buffer, 2), std::invalid_argument);
    // 'f' < char
    ASSERT_THROW(
        libzeth::hex_to_bytes("fg00", buffer, 2), std::invalid_argument);
}

} // namespace

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
