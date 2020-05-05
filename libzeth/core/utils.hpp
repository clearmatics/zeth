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

/// Decode hexidecimal string to an std::string of bytes.
std::string hex_to_bytes(const std::string &s);

/// Encode bytes as a hex string
std::string bytes_to_hex(const void *s, const size_t size);

/// Encode bytes as a hex string
std::string bytes_to_hex(const std::string &s);

/// Decode the (null-terminated) hex string to bytes, written to `dest_buffer`.
/// This function performs no bounds checking, so caller is responsible for
/// ensuring sufficient memory at `dest_buffer`. Use with caution. Returns the
/// number of bytes converted.
int hex_to_bytes(char *source_str, uint8_t *dest_buffer);

/// Function that erases the given `substring` from the string
/// passed as first argument.
void erase_substring(std::string &string, const std::string &substring);

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
