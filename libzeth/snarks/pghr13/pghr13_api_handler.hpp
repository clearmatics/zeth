// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SNARKS_PGHR13_PGHR13_API_HANDLER_HPP__
#define __ZETH_SNARKS_PGHR13_PGHR13_API_HANDLER_HPP__

#include "libzeth/core/extended_proof.hpp"
#include "libzeth/snarks/pghr13/pghr13_snark.hpp"

#include <zeth/api/snark_messages.pb.h>

namespace libzeth
{

/// Implementation of API-related functions for the PGHR13 snark.
template<typename ppT> class pghr13_api_handler
{
public:
    using snark = pghr13_snark<ppT>;

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

#include "libzeth/snarks/pghr13/pghr13_api_handler.tcc"

#endif // __ZETH_SNARKS_PGHR13_PGHR13_API_HANDLER_HPP__
