// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SNARKS_GROTH16_GROTH16_API_HANDLER_HPP__
#define __ZETH_SNARKS_GROTH16_GROTH16_API_HANDLER_HPP__

#include "libzeth/core/extended_proof.hpp"
#include "libzeth/snarks/groth16/groth16_snark.hpp"

#include <zeth/api/snark_messages.pb.h>

namespace libzeth
{

/// Implementation of API-related functions for the Groth16 snark.
template<typename ppT> class groth16_api_handler
{
public:
    using snark = groth16_snark<ppT>;

    static void verification_key_to_proto(
        const typename snark::verification_key &vk,
        zeth_proto::VerificationKey *message);

    static typename snark::verification_key verification_key_from_proto(
        const zeth_proto::VerificationKey &verification_key);

    static void extended_proof_to_proto(
        const extended_proof<ppT, snark> &ext_proof,
        zeth_proto::ExtendedProof *message);

    static libzeth::extended_proof<ppT, snark> extended_proof_from_proto(
        const zeth_proto::ExtendedProof &ext_proof);
};

} // namespace libzeth

#include "libzeth/snarks/groth16/groth16_api_handler.tcc"

#endif // __ZETH_SNARKS_GROTH16_GROTH16_API_HANDLER_HPP__
