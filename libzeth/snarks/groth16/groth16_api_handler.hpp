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

    static void format_extended_proof(
        const extended_proof<ppT, snarkT> &ext_proof,
        zeth_proto::ExtendedProof *message);

    static void format_verification_key(
        const typename snarkT::VerifKeyT &vk,
        zeth_proto::VerificationKey *message);

    static libzeth::extended_proof<ppT, snarkT> parse_extended_proof(
        const zeth_proto::ExtendedProof &ext_proof);

    static typename snarkT::VerifKeyT parse_verification_key(
        const zeth_proto::VerificationKey &verification_key);

    static void prepare_proof_response(
        const extended_proof<ppT, snarkT> &ext_proof,
        zeth_proto::ExtendedProof *message);

    static void prepare_verification_key_response(
        const typename snarkT::VerifKeyT &vk,
        zeth_proto::VerificationKey *message);
};

} // namespace libzeth

#include "libzeth/snarks/groth16/groth16_api_handler.tcc"

#endif // __ZETH_SNARKS_GROTH16_GROTH16_API_HANDLER_HPP__
