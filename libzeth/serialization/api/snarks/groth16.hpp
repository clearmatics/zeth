// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SERIALIZATION_API_SNARKS_HPP__
#define __ZETH_SERIALIZATION_API_SNARKS_HPP__

#include "api/snark_messages.grpc.pb.h"
// #include "libzeth/serialization/api/api_io.hpp"
#include "libzeth/snarks/groth16/core.hpp"
#include "libzeth/types/extended_proof.hpp"

namespace libzeth
{

template<typename ppT> class groth16api
{
    typedef groth16snark<ppT> snarkT;

    void format_extended_proof(
        extended_proof<ppT, snarkT> &ext_proof,
        zeth_proto::ExtendedProof *message);

    void format_verification_key(
        typename snarkT::VerifKeyT &vk, zeth_proto::VerificationKey *message);

    libzeth::extended_proof<ppT, snarkT> parse_extended_proof(
        const zeth_proto::ExtendedProof &ext_proof);

    typename groth16snark<ppT>::VerifKeyT parse_verification_key(
        const zeth_proto::VerificationKey &verification_key);

    void prepare_proof_response(
        extended_proof<ppT, snarkT> &ext_proof,
        zeth_proto::ExtendedProof *message);

    void prepare_verification_key_response(
        const typename snarkT::VerifKeyT &vk,
        zeth_proto::VerificationKey *message);
};

// template<typename ppT>
// void format_extendedProofGROTH16(
//     extended_proof<ppT> &ext_proof, zeth_proto::ExtendedProof *message);

// template<typename ppT>
// void format_verificationKeyGROTH16(
//     libsnark::r1cs_gg_ppzksnark_verification_key<ppT> &vk,
//     zeth_proto::VerificationKey *message);

// template<typename ppT>
// libzeth::extended_proof<ppT> parse_extendedProofGROTH16(
//     const zeth_proto::ExtendedProof &ext_proof);

// template<typename ppT>
// libsnark::r1cs_gg_ppzksnark_verification_key<ppT>
// parse_verificationKeyGROTH16(
//     const zeth_proto::VerificationKey &verification_key);

} // namespace libzeth
#include "libzeth/serialization/api/snarks/groth16.tcc"

#endif // __ZETH_SERIALIZATION_API_SNARKS_HPP__
