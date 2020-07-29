// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SERIALIZATION_R1CS_SERIALIZATION_HPP__
#define __ZETH_SERIALIZATION_R1CS_SERIALIZATION_HPP__

#include "libzeth/core/include_libff.hpp"
#include "libzeth/core/include_libsnark.hpp"

#include <ostream>

namespace libzeth
{

template<typename FieldT>
std::ostream &primary_inputs_write_json(
    std::ostream &os, const std::vector<FieldT> &public_inputs);

template<typename FieldT>
std::istream &primary_inputs_read_json(
    std::istream &is, std::vector<FieldT> &public_inputs);

template<typename ppT>
std::string accumulation_vector_to_json(
    const libsnark::accumulation_vector<libff::G1<ppT>> &acc_vector);

/// A valid string is on the form:
/// "[[\"0x...\", ..., \"0x...\"], ..., [\"0x...\", ... \"0x...\"]]"
/// As such, we verify the prefix and suffix of the input string to verify
/// that it starts with "[[" and finishes with "]]".
///
/// TODO: Have proper and more robust implementation.
template<typename ppT>
libsnark::accumulation_vector<libff::G1<ppT>> accumulation_vector_from_json(
    const std::string &acc_vector_str);

template<typename ppT>
std::ostream &r1cs_write_json(
    const libsnark::protoboard<libff::Fr<ppT>> &pb, std::ostream &s);

} // namespace libzeth

#include "libzeth/serialization/r1cs_serialization.tcc"

#endif // __ZETH_SERIALIZATION_R1CS_SERIALIZATION_HPP__
