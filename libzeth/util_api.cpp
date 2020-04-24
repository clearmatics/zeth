// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/util_api.hpp"

// Message formatting and parsing utility

namespace libzeth
{

zeth_note parse_zeth_note(const zeth_proto::ZethNote &note)
{
    bits256 note_apk = hex_digest_to_bits256(note.apk());
    bits64 note_value = hex_value_to_bits64(note.value());
    bits256 note_rho = hex_digest_to_bits256(note.rho());
    bits256 note_trap_r = hex_digest_to_bits256(note.trap_r());

    return zeth_note(note_apk, note_value, note_rho, note_trap_r);
}

} // namespace libzeth
