// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_UTIL_API_HPP__
#define __ZETH_UTIL_API_HPP__

#include "api/util.pb.h"

#include <libff/common/default_types/ec_pp.hpp>
#include <libzeth/libsnark_helpers/debug_helpers.hpp>
#include <libzeth/types/bits.hpp>
#include <libzeth/types/joinsplit.hpp>
#include <libzeth/types/note.hpp>
#include <libzeth/util.hpp>

namespace libzeth
{

zeth_note parse_zeth_note(const prover_proto::ZethNote &note);

template<typename FieldT> FieldT parse_merkle_node(std::string mk_node);

template<typename FieldT, size_t TreeDepth>
joinsplit_input<FieldT, TreeDepth> parse_joinsplit_input(
    const prover_proto::JoinsplitInput &input);

template<typename ppT>
prover_proto::HexPointBaseGroup1Affine format_hexPointBaseGroup1Affine(
    const libff::G1<ppT> &point);

template<typename ppT>
prover_proto::HexPointBaseGroup2Affine format_hexPointBaseGroup2Affine(
    const libff::G2<ppT> &point);

} // namespace libzeth
#include <libzeth/util_api.tcc>

#endif // __ZETH_UTIL_API_HPP__
