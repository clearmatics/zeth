// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_UTIL_API_HPP__
#define __ZETH_UTIL_API_HPP__

#include "api/snark_messages.pb.h"
#include "api/zeth_messages.pb.h"
#include "libzeth/libsnark_helpers/debug_helpers.hpp"
#include "libzeth/libsnark_helpers/extended_proof.hpp"
#include "libzeth/types/bits.hpp"
#include "libzeth/types/joinsplit.hpp"
#include "libzeth/types/note.hpp"
#include "libzeth/util.hpp"

#include <libff/common/default_types/ec_pp.hpp>

namespace libzeth
{

zeth_note parse_zeth_note(const zeth_proto::ZethNote &note);

template<typename FieldT> FieldT parse_merkle_node(std::string mk_node);

template<typename FieldT, size_t TreeDepth>
joinsplit_input<FieldT, TreeDepth> parse_joinsplit_input(
    const zeth_proto::JoinsplitInput &input);

template<typename ppT>
zeth_proto::HexPointBaseGroup1Affine format_hexPointBaseGroup1Affine(
    const libff::G1<ppT> &point);

template<typename ppT>
zeth_proto::HexPointBaseGroup2Affine format_hexPointBaseGroup2Affine(
    const libff::G2<ppT> &point);

template<typename ppT>
std::string format_primary_inputs(std::vector<libff::Fr<ppT>> public_inputs);

template<typename ppT>
libff::G1<ppT> parse_hexPointBaseGroup1Affine(
    const zeth_proto::HexPointBaseGroup1Affine &point);

template<typename ppT>
libff::G2<ppT> parse_hexPointBaseGroup2Affine(
    const zeth_proto::HexPointBaseGroup2Affine &point);

template<typename ppT>
std::vector<libff::Fr<ppT>> parse_str_primary_inputs(std::string input_str);

template<typename ppT>
libzeth::extended_proof<ppT> parse_groth16_extended_proof(
    const zeth_proto::ExtendedProof &ext_proof);

template<typename ppT>
libzeth::extended_proof<ppT> parse_pghr13_extended_proof(
    const zeth_proto::ExtendedProof &ext_proof);

template<typename ppT>
libzeth::extended_proof<ppT> parse_extended_proof(
    const zeth_proto::ExtendedProof &ext_proof);

template<typename ppT>
libsnark::accumulation_vector<libff::G1<ppT>> parse_str_accumulation_vector(
    std::string acc_vector_str);

template<typename ppT>
libsnark::r1cs_gg_ppzksnark_verification_key<ppT> parse_groth16_vk(
    const zeth_proto::VerificationKey &verification_key);

template<typename ppT>
libsnark::r1cs_ppzksnark_verification_key<ppT> parse_pghr13_vk(
    const zeth_proto::VerificationKey &verification_key);

template<typename ppT>
libzeth::verificationKeyT<ppT> parse_verification_key(
    const zeth_proto::VerificationKey &verification_key);

} // namespace libzeth
#include "libzeth/util_api.tcc"

#endif // __ZETH_UTIL_API_HPP__
