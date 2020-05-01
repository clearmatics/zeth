// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SNARKS_GROTH16_GROTH16_API_HANDLER_HPP__
#define __ZETH_SNARKS_GROTH16_GROTH16_API_HANDLER_HPP__

#include "libzeth/core/extended_proof.hpp"
#include "libzeth/snarks/groth16/groth16_snark.hpp"

#include <api/snark_messages.grpc.pb.h>

namespace libzeth
{

/// Implementation of API-related functions for the Groth16 snark.
template<typename ppT> class groth16_api_handler
{
public:
    using snarkT = groth16_snark<ppT>;

    static void extended_proof_to_proto(
        const extended_proof<ppT, snarkT> &ext_proof,
        zeth_proto::ExtendedProof *message);

    static void verification_key_to_proto(
        const typename snarkT::VerificationKeyT &vk,
        zeth_proto::VerificationKey *message);

    static libzeth::extended_proof<ppT, snarkT> extended_proof_from_proto(
        const zeth_proto::ExtendedProof &ext_proof);

    static typename snarkT::VerificationKeyT verification_key_from_proto(
        const zeth_proto::VerificationKey &verification_key);
};

} // namespace libzeth

#include "libzeth/snarks/groth16/groth16_api_handler.tcc"

#endif // __ZETH_SNARKS_GROTH16_GROTH16_API_HANDLER_HPP__
