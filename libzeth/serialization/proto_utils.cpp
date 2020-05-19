// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/serialization/proto_utils.hpp"

namespace libzeth
{

zeth_note zeth_note_from_proto(const zeth_proto::ZethNote &note)
{
    return zeth_note(
        bits256::from_hex(note.apk()),
        bits64::from_hex(note.value()),
        bits256::from_hex(note.rho()),
        bits256::from_hex(note.trap_r()));
}

} // namespace libzeth
