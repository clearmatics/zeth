// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/serialization/r1cs_serialization.hpp"

#include <gtest/gtest.h>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/curves/bls12_377/bls12_377_pp.hpp>
#include <libff/algebra/curves/bw6_761/bw6_761_pp.hpp>
#include <libff/algebra/curves/mnt/mnt4/mnt4_pp.hpp>
#include <libff/algebra/curves/mnt/mnt6/mnt6_pp.hpp>

namespace
{

template<typename ppT> void primary_inputs_json_encode_decode()
{
    using Fr = libff::Fr<ppT>;
    const std::vector<Fr> inputs{Fr(1), Fr(21), Fr(321), Fr(4321)};

    const std::string inputs_string = [&inputs]() {
        std::stringstream ss;
        libzeth::primary_inputs_write_json(ss, inputs);
        return ss.str();
    }();

    const std::vector<Fr> inputs_decoded = [&inputs_string]() {
        std::stringstream ss(inputs_string);
        std::vector<Fr> inputs;
        libzeth::primary_inputs_read_json(ss, inputs);
        return inputs;
    }();

    ASSERT_EQ(inputs, inputs_decoded);
}

template<typename ppT> void accumulation_vector_json_encode_decode()
{
    using G1 = libff::G1<ppT>;

    const libsnark::accumulation_vector<G1> acc_vect(
        G1::random_element(), {G1::random_element(), G1::random_element()});
    const std::string acc_vect_string =
        libzeth::accumulation_vector_to_json<ppT>(acc_vect);
    const libsnark::accumulation_vector<G1> acc_vect_decoded =
        libzeth::accumulation_vector_from_json<ppT>(acc_vect_string);
    const std::string acc_vect_decoded_string =
        libzeth::accumulation_vector_to_json<ppT>(acc_vect_decoded);

    ASSERT_EQ(acc_vect, acc_vect_decoded);
    ASSERT_EQ(acc_vect_string, acc_vect_decoded_string);
}

TEST(R1CSSerializationTest, PrimaryInputsJsonEncodeDecode)
{
    primary_inputs_json_encode_decode<libff::alt_bn128_pp>();
    primary_inputs_json_encode_decode<libff::mnt4_pp>();
    primary_inputs_json_encode_decode<libff::mnt6_pp>();
    primary_inputs_json_encode_decode<libff::bls12_377_pp>();
    primary_inputs_json_encode_decode<libff::bw6_761_pp>();
}

TEST(R1CSSerializationTest, AccumulationVectorJsonEncodeDecode)
{
    accumulation_vector_json_encode_decode<libff::alt_bn128_pp>();
    accumulation_vector_json_encode_decode<libff::mnt4_pp>();
    accumulation_vector_json_encode_decode<libff::mnt6_pp>();
    accumulation_vector_json_encode_decode<libff::bls12_377_pp>();
    accumulation_vector_json_encode_decode<libff::bw6_761_pp>();
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
