// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SERIALIZATION_PROTO_UTILS_HPP__
#define __ZETH_SERIALIZATION_PROTO_UTILS_HPP__

#include "libzeth/core/bits.hpp"
#include "libzeth/core/extended_proof.hpp"
#include "libzeth/core/group_element_utils.hpp"
#include "libzeth/core/include_libff.hpp"
#include "libzeth/core/include_libsnark.hpp"
#include "libzeth/core/joinsplit_input.hpp"
#include "libzeth/core/note.hpp"
#include "libzeth/core/utils.hpp"

#include <zeth/api/snark_messages.pb.h>
#include <zeth/api/zeth_messages.pb.h>

// Functions to convert between in-memory and protobuf types. Consistent with
// encoding functions for other types, we use the `<type>_to_proto` and
// `<type>_from_proto` naming everywhere.a

namespace libzeth
{

zeth_note zeth_note_from_proto(const zeth_proto::ZethNote &note);

template<typename ppT>
zeth_proto::Group1Point point_g1_affine_to_proto(const libff::G1<ppT> &point);

template<typename ppT>
libff::G1<ppT> point_g1_affine_from_proto(const zeth_proto::Group1Point &point);

template<typename ppT>
zeth_proto::Group2Point point_g2_affine_to_proto(const libff::G2<ppT> &point);

template<typename ppT>
libff::G2<ppT> point_g2_affine_from_proto(const zeth_proto::Group2Point &point);

template<typename FieldT, size_t TreeDepth>
joinsplit_input<FieldT, TreeDepth> joinsplit_input_from_proto(
    const zeth_proto::JoinsplitInput &input);

/// Populate a protobuf description of some pairing parameters
template<typename ppT>
void pp_to_proto(zeth_proto::PairingParameters &pp_proto);

} // namespace libzeth

#include "libzeth/serialization/proto_utils.tcc"

#endif // __ZETH_SERIALIZATION_PROTO_UTILS_HPP__
