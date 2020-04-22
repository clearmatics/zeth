// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SERIALIZATION_API_SNARKS_HPP__
#define __ZETH_SERIALIZATION_API_SNARKS_HPP__

#include "api/snark_messages.grpc.pb.h"
#include "libzeth/types/extended_proof.hpp"
#include "libzeth/serialization/api/api_io.hpp"

namespace libzeth
{

template<typename ppT>
void format_extendedProofPGHR13(
    extended_proof<ppT> &ext_proof, zeth_proto::ExtendedProof *message);

template<typename ppT>
void format_verificationKeyPGHR13(
    libsnark::r1cs_ppzksnark_verification_key<ppT> &vk,
    zeth_proto::VerificationKey *message);

template<typename ppT>
libzeth::extended_proof<ppT> parse_extendedProofPGHR13(
    const zeth_proto::ExtendedProof &ext_proof);

template<typename ppT>
libsnark::r1cs_ppzksnark_verification_key<ppT> parse_verificationKeyPGHR13(
    const zeth_proto::VerificationKey &verification_key);

} // namespace libzeth
#include "libzeth/serialiazation/api/snarks/pghr13.tcc"

#endif // __ZETH_SERIALIZATION_API_SNARKS_HPP__
