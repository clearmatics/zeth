// Copyright (c) 2015-2019 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_UTIL_HPP__
#define __ZETH_UTIL_HPP__

#include "types/bits.hpp"

#include <cstdint>
#include <gmp.h>
#include <libff/algebra/fields/bigint.hpp>
#include <string>
#include <vector>

namespace libzeth
{

template<typename T> T swap_bit_endianness(T v);
template<typename T> T swap_byte_endianness(T v);

std::vector<bool> hex_to_binary_vector(std::string str);
std::vector<bool> hex_digest_to_binary_vector(std::string str);
bits256 hex_digest_to_bits256(std::string digest_hex_str);
bits64 hex_value_to_bits64(std::string value_hex_str);

std::vector<bool> convert_int_to_binary(int x);
std::vector<bool> address_bits_from_address(int address, size_t tree_depth);

template<typename FieldT> FieldT string_to_field(std::string input);

std::string hexadecimal_str_to_binary_str(const std::string &s);
std::string binary_str_to_hexadecimal_str(const void *s, const size_t size);
std::string binary_str_to_hexadecimal_str(const std::string &s);

// interface for StructuredT typed below:
// {
//   bool is_well_formed() const;
// }

//  Throw if input is not well-formed.  The type being checked should conform
//  to the StructuredT interface above.
template<typename StructuredT>
void check_well_formed(const StructuredT &v, const char *name);

//  Throw if input is not well-formed.  The type being checked should conform
//  to the StructuredT interface above.
template<typename StructuredT>
void check_well_formed_(const StructuredT &v, const char *name);

//  For some iterable container of objects comforming to StructuredT, throw if
//  any entry is not well-formed.
template<typename StructuredTs>
bool container_is_well_formed(const StructuredTs &values);

} // namespace libzeth
#include "util.tcc"

#endif // __ZETH_UTIL_HPP__
