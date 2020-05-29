// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/core/group_element_utils.hpp"

#include <gtest/gtest.h>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

// Test data is specifically for alt_bn128
using ppT = libff::alt_bn128_pp;
using Fr = libff::Fr<ppT>;
using G1 = libff::G1<ppT>;
using G2 = libff::G2<ppT>;

namespace
{

TEST(GroupElementUtilsTest, G1EncodeDecodeJson)
{
    static const std::string g1_json_expected =
        "["
        "\"0x05e86f8cc8a7a4f10f56093465679f17f8b8c3fdb41469e408b529e030f52f3f\""
        ", "
        "\"0x2857bd14bbc09767bed8e913d3ccb42b2bc8738f715417dd6f020725d22bcd90\""
        "]";
    G1 g1 = Fr(13) * G1::one();
    g1.to_affine_coordinates();
    std::string g1_json = libzeth::point_g1_affine_to_json<ppT>(g1);
    G1 g1_decoded = libzeth::point_g1_affine_from_json<ppT>(g1_json);

    ASSERT_EQ(g1_json_expected, g1_json);
    ASSERT_EQ(g1, g1_decoded);
}

TEST(GroupElementUtilsTest, G2EncodeJson)
{
    static const std::string g2_json_expected =
        "[\n"
        "["
        "\"0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2\""
        ", "
        "\"0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed\""
        "],\n["
        "\"0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b\""
        ", "
        "\"0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa\""
        "]\n]";
    G2 g2 = G2::one();
    g2.to_affine_coordinates();
    std::string g2_json = libzeth::point_g2_affine_to_json<ppT>(g2);
    ASSERT_EQ(g2_json_expected, g2_json);
}

} // namespace

int main(int argc, char **argv)
{
    ppT::init_public_params();
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
