// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/serialization/proto_utils.hpp"

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/curves/bls12_377/bls12_377_pp.hpp>
#include <libff/algebra/curves/bw6_761/bw6_761_pp.hpp>

namespace libzeth
{

// Note, any attempt to call an implementation not given will result in a
// linker error.

template<> std::string pp_name<libff::alt_bn128_pp>()
{
    return std::string("alt-bn128");
}

template<> std::string pp_name<libff::bls12_377_pp>()
{
    return std::string("bls12-377");
}

template<> std::string pp_name<libff::bw6_761_pp>()
{
    return std::string("bw6-761");
}

zeth_note zeth_note_from_proto(const zeth_proto::ZethNote &note)
{
    return zeth_note(
        bits256::from_hex(note.apk()),
        bits64::from_hex(note.value()),
        bits256::from_hex(note.rho()),
        bits256::from_hex(note.trap_r()));
}

} // namespace libzeth
