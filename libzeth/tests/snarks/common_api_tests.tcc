// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include <gtest/gtest.h>

template<typename apiHandlerT> void verification_key_encode_decode_test()
{
    using snarkT = typename apiHandlerT::snarkT;

    const typename snarkT::VerificationKeyT initial_vk =
        snarkT::VerificationKeyT::dummy_verification_key(42);

    zeth_proto::VerificationKey proto_vk;
    apiHandlerT::verification_key_to_proto(initial_vk, &proto_vk);

    const typename snarkT::VerificationKeyT recovered_vk =
        apiHandlerT::verification_key_from_proto(proto_vk);
    ASSERT_EQ(initial_vk, recovered_vk);
}

template<typename ppT, typename apiHandlerT>
void extended_proof_encode_decode_test(
    const libzeth::extended_proof<ppT, typename apiHandlerT::snarkT> &proof)
{
    using snarkT = typename apiHandlerT::snarkT;

    zeth_proto::ExtendedProof proto_proof;
    apiHandlerT::extended_proof_to_proto(proof, &proto_proof);

    const libzeth::extended_proof<ppT, snarkT> recovered_proof =
        apiHandlerT::extended_proof_from_proto(proto_proof);

    ASSERT_EQ(proof.get_proof(), recovered_proof.get_proof());
    ASSERT_EQ(proof.get_primary_inputs(), recovered_proof.get_primary_inputs());
}
