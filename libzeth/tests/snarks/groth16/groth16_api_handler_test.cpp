// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/serialization/proto_utils.hpp"
#include "libzeth/snarks/groth16/groth16_api_handler.hpp"
#include "libzeth/tests/snarks/common_api_tests.tcc"
#include "zeth_config.h"

#include <gtest/gtest.h>

using Fr = libff::Fr<ppT>;
using G1 = libff::G1<ppT>;
using G2 = libff::G2<ppT>;
using snark = libzeth::groth16_snark<ppT>;

namespace
{

TEST(Groth16ApiHandlerTest, VerificationKeyEncodeDecode)
{
    verification_key_encode_decode_test<libzeth::groth16_api_handler<ppT>>();
}

TEST(Groth16ApiHandlerTest, ProofEncodeDecode)
{
    snark::ProofT dummy_proof{
        G1::random_element(), G2::random_element(), G1::random_element()};
    libsnark::r1cs_primary_input<Fr> dummy_inputs{
        Fr::random_element(), Fr::random_element(), Fr::random_element()};
    extended_proof_encode_decode_test<ppT, libzeth::groth16_api_handler<ppT>>(
        {std::move(dummy_proof), std::move(dummy_inputs)});
}

} // namespace

int main(int argc, char **argv)
{
    ppT::init_public_params();
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
