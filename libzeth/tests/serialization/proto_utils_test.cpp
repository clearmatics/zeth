// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/circuits/circuit_types.hpp"
#include "libzeth/serialization/proto_utils.hpp"

#include <gtest/gtest.h>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/curves/bls12_377/bls12_377_pp.hpp>
#include <libff/algebra/curves/bw6_761/bw6_761_pp.hpp>
#include <libff/algebra/curves/mnt/mnt4/mnt4_pp.hpp>
#include <libff/algebra/curves/mnt/mnt6/mnt6_pp.hpp>

namespace
{

template<typename ppT> void point_g1_affine_encode_decode()
{
    using Fr = libff::Fr<ppT>;
    using G1 = libff::G1<ppT>;

    G1 g1 = Fr(13) * G1::one();
    g1.to_affine_coordinates();
    zeth_proto::HexPointBaseGroup1Affine g1_proto =
        libzeth::point_g1_affine_to_proto<ppT>(g1);
    const G1 g1_decoded = libzeth::point_g1_affine_from_proto<ppT>(g1_proto);

    ASSERT_EQ(g1, g1_decoded);
}

template<typename ppT> void point_g2_affine_encode_decode_test()
{
    using Fr = libff::Fr<ppT>;
    using G2 = libff::G2<ppT>;

    G2 g2 = Fr(13) * G2::one();
    g2.to_affine_coordinates();
    zeth_proto::HexPointBaseGroup2Affine g2_proto =
        libzeth::point_g2_affine_to_proto<ppT>(g2);
    const G2 g2_decoded = libzeth::point_g2_affine_from_proto<ppT>(g2_proto);

    ASSERT_EQ(g2, g2_decoded);
}

// TODO: Add test for joinsplit_input_from_proto

TEST(ProtoUtilsTest, PointG1AffineEncodeDecode)
{
    point_g1_affine_encode_decode<libff::alt_bn128_pp>();
    point_g1_affine_encode_decode<libff::mnt4_pp>();
    point_g1_affine_encode_decode<libff::mnt6_pp>();
    point_g1_affine_encode_decode<libff::bls12_377_pp>();
    point_g1_affine_encode_decode<libff::bw6_761_pp>();
}

TEST(ProtoUtilsTest, PointG2AffineEncodeDecode)
{
    point_g2_affine_encode_decode_test<libff::alt_bn128_pp>();
    point_g2_affine_encode_decode_test<libff::mnt4_pp>();
    point_g2_affine_encode_decode_test<libff::mnt6_pp>();
    point_g2_affine_encode_decode_test<libff::bls12_377_pp>();
    point_g2_affine_encode_decode_test<libff::bw6_761_pp>();
}

} // namespace

int main(int argc, char **argv)
{
    libff::alt_bn128_pp::init_public_params();
    libff::mnt4_pp::init_public_params();
    libff::mnt6_pp::init_public_params();
    libff::bls12_377_pp::init_public_params();
    libff::bw6_761_pp::init_public_params();
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
