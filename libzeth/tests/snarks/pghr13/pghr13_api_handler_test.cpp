// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/circuits/circuit_types.hpp"
#include "libzeth/serialization/proto_utils.hpp"
#include "libzeth/snarks/pghr13/pghr13_api_handler.hpp"

#include <gtest/gtest.h>

using ppT = libzeth::ppT;
using Fr = libff::Fr<libzeth::ppT>;
using G1 = libff::G1<libzeth::ppT>;
using G2 = libff::G2<libzeth::ppT>;

namespace
{

TEST(PGHR13ApiHandlerTest, VerificationKeyEncodeDecode)
{
    libsnark::r1cs_ppzksnark_verification_key<ppT> initial_vk =
        libsnark::r1cs_ppzksnark_verification_key<ppT>::dummy_verification_key(
            42);

    zeth_proto::VerificationKey *proto_vk = new zeth_proto::VerificationKey();
    libzeth::pghr13_api_handler<ppT>::verification_key_to_proto(
        initial_vk, proto_vk);

    libsnark::r1cs_ppzksnark_verification_key<ppT> recovered_vk =
        libzeth::pghr13_api_handler<ppT>::verification_key_from_proto(
            *proto_vk);

    ASSERT_EQ(initial_vk, recovered_vk);

    // The destructor of `zeth_proto::VerificationKey` should be
    // invoked which whould free the memory allocated for the fields of this
    // message
    delete proto_vk;
}

} // namespace

int main(int argc, char **argv)
{
    ppT::init_public_params();
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}