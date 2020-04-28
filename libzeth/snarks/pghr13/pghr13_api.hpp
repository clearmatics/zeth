// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SNARKS_PGHR13_PGHR13_API_HPP__
#define __ZETH_SNARKS_PGHR13_PGHR13_API_HPP__

#include "api/snark_messages.grpc.pb.h"
#include "libzeth/snarks/pghr13/pghr13_core.hpp"
#include "libzeth/types/extended_proof.hpp"

namespace libzeth
{

/// Implemetation of API-related functions for the Groth16 snark.
template<typename ppT> class pghr13api
{
public:
    using snarkT = pghr13snark<ppT>;

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

#include "libzeth/snarks/pghr13/pghr13_api.tcc"

#endif // __ZETH_SNARKS_PGHR13_PGHR13_API_HPP__
