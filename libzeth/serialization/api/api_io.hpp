// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SERIALIZATION_API_IO_HPP__
#define __ZETH_SERIALIZATION_API_IO_HPP__

#include "api/snark_messages.pb.h"
#include "api/zeth_messages.pb.h"
#include "libzeth/types/bits.hpp"
#include "libzeth/types/extended_proof.hpp"
#include "libzeth/types/joinsplit.hpp"
#include "libzeth/types/note.hpp"
#include "libzeth/util.hpp"

#include <libff/common/default_types/ec_pp.hpp>

/// This set of function allows to consume RPC calls data
/// and to format zeth data structures into proto messages

namespace libzeth
{

zeth_note parse_zeth_note(const zeth_proto::ZethNote &note);

template<typename FieldT> FieldT parse_merkle_node(std::string mk_node);

template<typename FieldT, size_t TreeDepth>
joinsplit_input<FieldT, TreeDepth> parse_joinsplit_input(
    const zeth_proto::JoinsplitInput &input);

template<typename ppT>
libff::G1<ppT> parse_hexPointBaseGroup1Affine(
    const zeth_proto::HexPointBaseGroup1Affine &point);

template<typename ppT>
libff::G2<ppT> parse_hexPointBaseGroup2Affine(
    const zeth_proto::HexPointBaseGroup2Affine &point);

template<typename ppT>
std::vector<libff::Fr<ppT>> parse_str_primary_inputs(std::string input_str);

template<typename ppT, typename snarkT>
libzeth::extended_proof<ppT, snarkT> parse_extended_proof(
    const zeth_proto::ExtendedProof &ext_proof);

template<typename ppT>
libsnark::accumulation_vector<libff::G1<ppT>> parse_str_accumulation_vector(
    std::string acc_vector_str);

template<typename ppT, typename snarkT>
typename snarkT::VerifKeyT parse_verification_key(
    const zeth_proto::VerificationKey &verification_key);

template<typename ppT>
zeth_proto::HexPointBaseGroup1Affine format_hexPointBaseGroup1Affine(
    const libff::G1<ppT> &point);

template<typename ppT>
zeth_proto::HexPointBaseGroup2Affine format_hexPointBaseGroup2Affine(
    const libff::G2<ppT> &point);

template<typename ppT>
std::string format_primary_inputs(std::vector<libff::Fr<ppT>> public_inputs);

template<typename ppT, typename snarkApiT>
void format_extendedProof(
    extended_proof<ppT, typename snarkApiT::snarkT> &ext_proof,
    zeth_proto::ExtendedProof *message);

template<typename ppT>
std::string format_accumulation_vector(std::vector<libff::Fr<ppT>> acc_vector);

template<typename ppT, typename snarkApiT>
void format_verificationKey(
    const typename snarkApiT::snarkT::VerifKeyT &vk,
    // libsnark::r1cs_gg_ppzksnark_verification_key<ppT> &vk,
    zeth_proto::VerificationKey *message);

} // namespace libzeth

// // snark-specific include depends on the functions above
// #include "libzeth/serialization/api/snarks_api_imports.hpp"

// templatized implementations
#include "libzeth/serialization/api/api_io.tcc"

#endif // __ZETH_SERIALIZATION_API_IO_HPP__
