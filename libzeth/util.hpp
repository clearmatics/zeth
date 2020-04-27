// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_UTIL_HPP__
#define __ZETH_UTIL_HPP__

#include "libzeth/types/bits.hpp"

#include <cstdint>
#include <gmp.h>
#include <string>
#include <vector>

namespace libzeth
{

// template<typename StructuredT>
// bool is_well_formed(const StructuredT &structured);
// {
//     return structured.is_well_formed();
// }

// template<> bool well_formed_checker<int>::is_well_formed(const int &)
// {
//     return true;
// }

// /// Function required by `check_well_formed_`
// template<typename StructuredT>
// bool is_well_formed(const StructuredT &);

/// Takes a container with a `size()` method and reverse the order
/// of the elements. The elements should represent bits.
template<typename T> T swap_byte_endianness(T v);

/// Returns the binary encoding of the address of a leaf node in a binary tree.
/// The resulting binary encoding is correctly padded such that its length
/// corresponds to the depth of the tree.
/// This function throws an exception if called for an `address` which
/// is bigger than the MAX_ADDRESS = 2^{TreeDepth}
template<size_t TreeDepth>
std::vector<bool> address_bits_from_address(size_t address);

/// Takes an hexadecimal string and converts it into a binary vector.
/// This function throws an exception if called with an invalid hexadecimal
/// string.
std::vector<bool> hexadecimal_str_to_binary_vector(std::string str);

/// Takes an hexadecimal digest and converts it into a binary vector.
/// This function throws an exception if called with an invalid hexadecimal
/// digest.
std::vector<bool> hexadecimal_digest_to_binary_vector(std::string str);

// Returns the little endian binary encoding of the integer x.
std::vector<bool> convert_uint_to_binary(size_t x);

std::string hexadecimal_str_to_binary_str(const std::string &s);
std::string binary_str_to_hexadecimal_str(const void *s, const size_t size);
std::string binary_str_to_hexadecimal_str(const std::string &s);

/// Takes an hexadecimal string and converts it to an array of bytes (uint8_t*).
/// The result is written in the `dest_buffer` passed as argument during the
/// function call.
/// The function returns the number of bytes converted.
int hexadecimal_str_to_byte_array(char *source_str, uint8_t *dest_buffer);

/// Function that erases the given `substring` from the string
/// passed as first argument.
void erase_substring(std::string &string, const std::string &substring);

/// interface for StructuredT typed below:
/// {
///   bool is_well_formed() const;
/// }
///
/// Throw if input is not well-formed. The type being checked should conform
/// to the StructuredT interface above.
template<typename StructuredT>
void check_well_formed(const StructuredT &v, const char *name);

// /// Throw if input is not well-formed. The type being checked should conform
// /// to the StructuredT interface above.
// template<typename StructuredT>
// void check_well_formed_(const StructuredT &v, const char *name);

/// For some iterable container of objects comforming to StructuredT, throw if
/// any entry is not well-formed.
template<typename StructuredTs>
bool container_is_well_formed(const StructuredTs &values);

} // namespace libzeth
#include "libzeth/util.tcc"

#endif // __ZETH_UTIL_HPP__
