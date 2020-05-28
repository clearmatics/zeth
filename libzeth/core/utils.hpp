// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CORE_UTILS_HPP__
#define __ZETH_CORE_UTILS_HPP__

#include "libzeth/core/bits.hpp"

#include <cstdint>
#include <gmp.h>
#include <string>
#include <vector>

namespace libzeth
{

/// Takes a container with a `size()` method containing a multiple of 8
/// elements. The elements (considered to be bit-like) are divided into "bytes"
/// (groups of 8), and the order of these "bytes" is reversed. The order of
/// "bits" within each "byte" is preserved.
template<typename T> T swap_byte_endianness(T v);

/// Convert a single character to a nibble (uint8_t < 0x10). Throws
/// `std::invalid_argument` if the character is invalid.
uint8_t char_to_nibble(const char c);

/// Convert hex to bytes (first chars at lowest address)
void hex_to_bytes(const std::string &hex, void *dest, size_t bytes);

/// Convert hex to bytes (first chars at highest address, for little-endian
/// numbers, etc)
void hex_to_bytes_reversed(const std::string &hex, void *dest, size_t bytes);

/// Decode hexidecimal string to an std::string of bytes.
std::string hex_to_bytes(const std::string &s);

/// Encode bytes as a hex string
std::string bytes_to_hex(const void *bytes, size_t num_bytes);

/// Encode bytes as a hex string
std::string bytes_to_hex_reversed(const void *bytes, size_t num_bytes);

/// Convenience function to throw if input is not well-formed. Here StructuredT
/// is assumed to have the form:
///
/// {
///   bool is_well_formed() const;
/// }
template<typename StructuredT>
void check_well_formed(const StructuredT &v, const char *name);

/// For some iterable container of objects comforming to StructuredT, throw if
/// any entry is not well-formed.
template<typename StructuredTs>
bool container_is_well_formed(const StructuredTs &values);

} // namespace libzeth

#include "libzeth/core/utils.tcc"

#endif // __ZETH_CORE_UTILS_HPP__
