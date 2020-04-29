// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CORE_BITS_HPP__
#define __ZETH_CORE_BITS_HPP__

#include <array>
#include <iostream>
#include <stddef.h>
#include <vector>

/// Bit-arrays of specific sizes, and related methods.

namespace libzeth
{

/// Array of 32 bits
using bits32 = std::array<bool, 32>;

std::vector<bool> bits32_to_vector(const bits32 &arr);

/// Array of 64 bits
using bits64 = std::array<bool, 64>;

bits64 bits64_from_vector(const std::vector<bool> &vect);

bits64 bits64_from_hex(const std::string &hex_str);

std::vector<bool> bits64_to_vector(const bits64 &arr);

/// Array of 256 bits
using bits256 = std::array<bool, 256>;

bits256 bits256_from_vector(const std::vector<bool> &vect);

bits256 bits256_from_hex(const std::string &hex_str);

std::vector<bool> bits256_to_vector(const bits256 &arr);

/// Array of 384 bits
using bits384 = std::array<bool, 384>;

/// "Construct" `bits` types from boolean vectors
bits384 bits384_from_vector(const std::vector<bool> &vect);

/// "Construct" `bits` types from hexadecimal strings
bits384 bits384_from_hex(const std::string &hex_str);

/// Retrieve boolean vectors from `bits` types
std::vector<bool> bits384_to_vector(const bits384 &arr);

/// Bit-array representing an "address" in a tree.
template<size_t TreeDepth> using bits_addr = std::array<bool, TreeDepth>;

template<size_t TreeDepth>
bits_addr<TreeDepth> bits_addr_from_vector(const std::vector<bool> &vect);

template<size_t TreeDepth>
std::vector<bool> bits_addr_to_vector(const bits_addr<TreeDepth> &arr);

/// Returns the binary encoding of the address of a leaf node in a binary tree.
/// The resulting binary encoding is correctly padded such that its length
/// corresponds to the depth of the tree.
/// This function throws an exception if called for an `address` which
/// is bigger than the MAX_ADDRESS = 2^{TreeDepth}
template<size_t TreeDepth>
bits_addr<TreeDepth> bits_addr_from_size_t(size_t address);

/// XOR two binary strings of the same length.
/// The strings are represented as arrays of booleans.
template<size_t BitLen>
std::array<bool, BitLen> bits_xor(
    const std::array<bool, BitLen> &a, const std::array<bool, BitLen> &b);

/// Sum 2 binary strings with or without carry
template<size_t BitLen>
std::array<bool, BitLen> bits_add(
    const std::array<bool, BitLen> &a,
    const std::array<bool, BitLen> &b,
    bool with_carry = false);

/// Takes a hexadecimal string and converts it into a bit-vector. Throws an
/// exception if called with an invalid hexadecimal string.
std::vector<bool> bit_vector_from_hex(const std::string &str);

// Returns the little endian binary encoding of the integer x.
std::vector<bool> bit_vector_from_size_t(size_t x);

} // namespace libzeth

#include "libzeth/core/bits.tcc"

#endif // __ZETH_CORE_BITS_HPP__
