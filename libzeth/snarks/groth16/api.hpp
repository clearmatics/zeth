// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SNARKS_GROTH16_API_HPP__
#define __ZETH_SNARKS_GROTH16_API_HPP__

#include "api/snark_messages.grpc.pb.h"
#include "libzeth/snarks/groth16/core.hpp"
#include "libzeth/types/extended_proof.hpp"

namespace libzeth
{

/// Implemetation of API-related functions for the Groth16 snark.
template<typename ppT> class groth16api
{
public:
    typedef groth16snark<ppT> snarkT;

    static void format_extended_proof(
        extended_proof<ppT, snarkT> &ext_proof,
        zeth_proto::ExtendedProof *message);

    static void format_verification_key(
        typename snarkT::VerifKeyT &vk, zeth_proto::VerificationKey *message);

    static libzeth::extended_proof<ppT, snarkT> parse_extended_proof(
        const zeth_proto::ExtendedProof &ext_proof);

    static typename groth16snark<ppT>::VerifKeyT parse_verification_key(
        const zeth_proto::VerificationKey &verification_key);

    static void prepare_proof_response(
        extended_proof<ppT, snarkT> &ext_proof,
        zeth_proto::ExtendedProof *message);

    static void prepare_verification_key_response(
        const typename snarkT::VerifKeyT &vk,
        zeth_proto::VerificationKey *message);
};

} // namespace libzeth

#include "libzeth/snarks/groth16/api.tcc"

#endif // __ZETH_SNARKS_GROTH16_API_HPP__
