// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/circuits/circuit_types.hpp"
#include "libzeth/serialization/proto_utils.hpp"
#include "zeth_config.h"

#include <gtest/gtest.h>

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

template<typename ppT> void primary_inputs_encode_decode()
{
    using Fr = libff::Fr<ppT>;

    const std::vector<Fr> inputs{Fr(1), Fr(21), Fr(321), Fr(4321)};
    std::string inputs_string = libzeth::primary_inputs_to_string<ppT>(inputs);
    std::cout << "inputs_string: " << inputs_string << std::endl;
    const std::vector<Fr> inputs_decoded =
        libzeth::primary_inputs_from_string<ppT>(inputs_string);
    ASSERT_EQ(inputs, inputs_decoded);
}

template<typename ppT> void accumulation_vector_encode_decode()
{
    using G1 = libff::G1<ppT>;

    const libsnark::accumulation_vector<G1> acc_vect(
        G1::random_element(), {G1::random_element(), G1::random_element()});
    const std::string acc_vect_string =
        libzeth::accumulation_vector_to_string<ppT>(acc_vect);
    const libsnark::accumulation_vector<G1> acc_vect_decoded =
        libzeth::accumulation_vector_from_string<ppT>(acc_vect_string);
    const std::string acc_vect_decoded_string =
        libzeth::accumulation_vector_to_string<ppT>(acc_vect_decoded);

    ASSERT_EQ(acc_vect, acc_vect_decoded);
    ASSERT_EQ(acc_vect_string, acc_vect_decoded_string);
}

TEST(ProtoUtilsTest, PointG1AffineEncodeDecode)
{
    point_g1_affine_encode_decode<libff::alt_bn128_pp>();
}

TEST(ProtoUtilsTest, PointG2AffineEncodeDecode)
{
    point_g2_affine_encode_decode_test<libff::alt_bn128_pp>();
}

TEST(ProtoUtilsTest, PrimaryInputsEncodeDecode)
{
    primary_inputs_encode_decode<libff::alt_bn128_pp>();
}

TEST(ProtoUtilsTest, AccumulationVectorEncodeDecode)
{
    accumulation_vector_encode_decode<libff::alt_bn128_pp>();
}

} // namespace

int main(int argc, char **argv)
{
    libff::alt_bn128_pp::init_public_params();
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
