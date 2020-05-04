// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/serialization/proto_utils.hpp"

namespace libzeth
{

zeth_note zeth_note_from_proto(const zeth_proto::ZethNote &note)
{
    bits256 note_apk = bits256_from_hex(note.apk());
    bits64 note_value = bits64_from_hex(note.value());
    bits256 note_rho = bits256_from_hex(note.rho());
    bits256 note_trap_r = bits256_from_hex(note.trap_r());

    return zeth_note(note_apk, note_value, note_rho, note_trap_r);
}

} // namespace libzeth
