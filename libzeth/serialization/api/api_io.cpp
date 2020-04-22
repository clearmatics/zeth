// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/serialization/api/api_io.hpp"

namespace libzeth
{

zeth_note parse_zeth_note(const zeth_proto::ZethNote &note)
{
    bits256 note_apk = get_bits256_from_hexadecimal_str(note.apk());
    bits64 note_value = get_bits64_from_hexadecimal_str(note.value());
    bits256 note_rho = get_bits256_from_hexadecimal_str(note.rho());
    bits384 note_trap_r = get_bits384_from_hexadecimal_str(note.trap_r());

    return zeth_note(note_apk, note_value, note_rho, note_trap_r);
}

} // namespace libzeth
