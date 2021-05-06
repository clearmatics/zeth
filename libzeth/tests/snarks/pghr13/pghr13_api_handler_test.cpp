// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/serialization/proto_utils.hpp"
#include "libzeth/snarks/pghr13/pghr13_api_handler.hpp"
#include "libzeth/tests/snarks/common_api_tests.tcc"
#include "zeth_config.h"

#include <gtest/gtest.h>

using pp = libzeth::defaults::pp;
using Fr = libff::Fr<pp>;
using G1 = libff::G1<pp>;
using G2 = libff::G2<pp>;
using snark = libzeth::pghr13_snark<pp>;

namespace
{

TEST(PGHR13ApiHandlerTest, VerificationKeyEncodeDecode)
{
    verification_key_encode_decode_json_test<libzeth::pghr13_api_handler<pp>>();
}

TEST(PGHR13ApiHandlerTest, ProofEncodeDecode)
{
    snark::proof dummy_proof(
        {G1::random_element(), G1::random_element()},
        {G2::random_element(), G1::random_element()},
        {G1::random_element(), G1::random_element()},
        G1::random_element(),
        G1::random_element());
    libsnark::r1cs_primary_input<Fr> dummy_inputs{
        Fr::random_element(), Fr::random_element(), Fr::random_element()};
    extended_proof_encode_decode_json_test<pp, libzeth::pghr13_api_handler<pp>>(
        {std::move(dummy_proof), std::move(dummy_inputs)});
}

} // namespace

int main(int argc, char **argv)
{
    pp::init_public_params();
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
