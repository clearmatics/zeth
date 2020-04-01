// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/snarks/groth16/mpc/hash_utils.hpp"
#include "libzeth/util.hpp"

#include <gtest/gtest.h>

namespace libzeth
{
namespace tests
{

TEST(MPCHashTests, HashInterface)
{
    // in: ""
    // out: 786a....be2ce
    {
        uint8_t empty[0];
        srs_mpc_hash_t hash;
        srs_mpc_compute_hash(hash, empty, 0);
        ASSERT_EQ(
            binary_str_to_hexadecimal_str((const char *)(&hash), sizeof(hash)),
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d2"
            "5e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce");
    }

    // in: "The quick brown fox jumps over the lazy dog"
    // out: a8ad....a918
    const std::string s = "The quick brown fox jumps over the lazy dog";
    const std::string expect_hash_hex =
        "a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673f82401"
        "cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918";
    {
        srs_mpc_hash_t hash;
        srs_mpc_compute_hash(hash, s);
        ASSERT_EQ(
            expect_hash_hex,
            binary_str_to_hexadecimal_str((const char *)(&hash), sizeof(hash)));
    }
    {
        srs_mpc_hash_t hash;
        hash_ostream hs;
        hs << s;
        hs.get_hash(hash);
        ASSERT_EQ(
            expect_hash_hex,
            binary_str_to_hexadecimal_str((const char *)(&hash), sizeof(hash)));
    }
}

TEST(MPCHashTests, HashRepresentation)
{
    const uint8_t empty[0]{};
    const std::string expected_hash_string =
        "786a02f7 42015903 c6c6fd85 2552d272\n"
        "912f4740 e1584761 8a86e217 f71f5419\n"
        "d25e1031 afee5853 13896444 934eb04b\n"
        "903a685b 1448b755 d56f701a fe9be2ce\n";

    srs_mpc_hash_t hash;
    srs_mpc_compute_hash(hash, empty, 0);

    // Write to stream
    const std::string hash_string = [&]() {
        std::ostringstream ss;
        srs_mpc_hash_write(hash, ss);
        return ss.str();
    }();
    ASSERT_EQ(expected_hash_string, hash_string);

    // Read from stream
    srs_mpc_hash_t hash_from_string;
    {
        std::istringstream ss(hash_string);
        ASSERT_TRUE(srs_mpc_hash_read(hash_from_string, ss));
    }
    ASSERT_EQ(0, memcmp(hash, hash_from_string, sizeof(srs_mpc_hash_t)));
}

TEST(MPCHashTests, HashOStreamWrapper)
{
    const std::string s = "The quick brown fox jumps over the lazy dog";
    const std::string expect_hash_hex =
        "a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673f82401"
        "cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918";

    // Create string stream and hash stream wrapper
    std::ostringstream ss;
    hash_ostream_wrapper hsw(ss);
    hsw << s;

    // Extract hash and data from wrapped stream
    srs_mpc_hash_t hash;
    hsw.get_hash(hash);
    std::string stream_data(ss.str());

    // Test
    ASSERT_EQ(s, stream_data);
    ASSERT_EQ(
        expect_hash_hex, binary_str_to_hexadecimal_str(hash, sizeof(hash)));
}

TEST(MPCHashTests, HashIStreamWrapper)
{
    const std::string s = "The quick brown fox jumps over the lazy dog";
    const std::string expect_hash_hex =
        "a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673f82401"
        "cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918";

    // Create string stream and hash stream wrapper
    std::istringstream ss(s);
    hash_istream_wrapper hsw(ss);

    // Stream data
    std::string stream_data;
    stream_data.resize(s.size(), ' ');
    hsw.read(&stream_data[0], s.size());

    // Extract hash and data from wrapped stream
    srs_mpc_hash_t hash;
    hsw.get_hash(hash);

    // Test
    ASSERT_EQ(s, stream_data);
    ASSERT_EQ(
        expect_hash_hex, binary_str_to_hexadecimal_str(hash, sizeof(hash)));
}

} // namespace tests

} // namespace libzeth
