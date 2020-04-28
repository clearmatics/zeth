// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CORE_BITS_HPP__
#define __ZETH_CORE_BITS_HPP__

#include <array>
#include <iostream>
#include <stddef.h>
#include <vector>

namespace libzeth
{

typedef std::array<bool, 384> bits384;
typedef std::array<bool, 256> bits256;
typedef std::array<bool, 64> bits64;
typedef std::array<bool, 32> bits32;
template<size_t TreeDepth> using bits_addr = std::array<bool, TreeDepth>;

/// Pour content of boolean vector into an array of booleans
template<size_t Size>
std::array<bool, Size> dump_vector_in_array(std::vector<bool> vect);

/// "Construct" `bits` types from boolean vectors
bits384 get_bits384_from_vector(std::vector<bool> vect);
bits256 get_bits256_from_vector(std::vector<bool> vect);
bits64 get_bits64_from_vector(std::vector<bool> vect);
template<size_t TreeDepth>
bits_addr<TreeDepth> get_bits_addr_from_vector(const std::vector<bool> &vect);

/// "Construct" `bits` types from hexadecimal strings
bits384 get_bits384_from_hexadecimal_str(std::string hex_str);
bits256 get_bits256_from_hexadecimal_str(std::string hex_str);
bits64 get_bits64_from_hexadecimal_str(std::string hex_str);

/// Pour content of boolean array into a vector of booleans
template<size_t Size>
std::vector<bool> dump_array_in_vector(std::array<bool, Size> arr);

/// Retrieve boolean vectors from `bits` types
std::vector<bool> get_vector_from_bits384(bits384 arr);
std::vector<bool> get_vector_from_bits256(bits256 arr);
std::vector<bool> get_vector_from_bits64(bits64 arr);
std::vector<bool> get_vector_from_bits32(bits32 arr);
template<size_t TreeDepth>
std::vector<bool> get_vector_from_bits_addr(const bits_addr<TreeDepth> &arr);

/// XOR two binary strings of the same length.
/// The strings are represented as arrays of booleans.
template<size_t BitLen>
std::array<bool, BitLen> binary_xor(
    std::array<bool, BitLen> A, std::array<bool, BitLen> B);

/// Sum two binary strings of the same length.
/// The strings are represented as arrays of booleans.
template<size_t BitLen>
std::array<bool, BitLen> binary_addition(
    std::array<bool, BitLen> A,
    std::array<bool, BitLen> B,
    bool withCarry = false);

} // namespace libzeth

#include "libzeth/core/bits.tcc"

#endif // __ZETH_CORE_BITS_HPP__
