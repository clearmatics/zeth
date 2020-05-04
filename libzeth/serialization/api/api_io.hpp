// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SERIALIZATION_API_IO_HPP__
#define __ZETH_SERIALIZATION_API_IO_HPP__

#include "libzeth/core/bits.hpp"
#include "libzeth/core/extended_proof.hpp"
#include "libzeth/core/include_libff.hpp"
#include "libzeth/core/include_libsnark.hpp"
#include "libzeth/core/joinsplit_input.hpp"
#include "libzeth/core/note.hpp"
#include "libzeth/core/utils.hpp"

#include <api/snark_messages.pb.h>
#include <api/zeth_messages.pb.h>

/// This set of function allows to consume RPC calls data
/// and to format zeth data structures into proto messages

namespace libzeth
{

zeth_note zeth_note_from_proto(const zeth_proto::ZethNote &note);

template<typename FieldT, size_t TreeDepth>
joinsplit_input<FieldT, TreeDepth> parse_joinsplit_input(
    const zeth_proto::JoinsplitInput &input);

template<typename ppT>
libff::G1<ppT> point_g1_affine_from_proto(
    const zeth_proto::HexPointBaseGroup1Affine &point);

template<typename ppT>
libff::G2<ppT> point_g2_affine_from_proto(
    const zeth_proto::HexPointBaseGroup2Affine &point);

template<typename ppT>
std::vector<libff::Fr<ppT>> parse_str_primary_inputs(std::string input_str);

template<typename ppT>
libsnark::accumulation_vector<libff::G1<ppT>> parse_str_accumulation_vector(
    std::string acc_vector_str);

template<typename ppT>
zeth_proto::HexPointBaseGroup1Affine format_hexPointBaseGroup1Affine(
    const libff::G1<ppT> &point);

template<typename ppT>
zeth_proto::HexPointBaseGroup2Affine format_hexPointBaseGroup2Affine(
    const libff::G2<ppT> &point);

template<typename ppT>
std::string primary_inputs_to_string(std::vector<libff::Fr<ppT>> public_inputs);

template<typename ppT, typename snarkApiT>
void extended_proof_to_proto(
    extended_proof<ppT, typename snarkApiT::snarkT> &ext_proof,
    zeth_proto::ExtendedProof *message);

template<typename ppT>
std::string accumulation_vector_to_string(std::vector<libff::Fr<ppT>> acc_vector);

} // namespace libzeth

// templatized implementations
#include "libzeth/serialization/api/api_io.tcc"

#endif // __ZETH_SERIALIZATION_API_IO_HPP__
