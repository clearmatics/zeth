// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_TYPES_BITS_HPP__
#define __ZETH_TYPES_BITS_HPP__

#include "zeth.h"

#include <array>
#include <iostream>
#include <vector>

namespace libzeth
{

typedef std::array<bool, 384> bits384;
typedef std::array<bool, 256> bits256;
typedef std::array<bool, 64> bits64;
typedef std::array<bool, 32> bits32;
template<size_t TreeDepth> using bits_addr = std::array<bool, TreeDepth>;

// Dump a vector into an array
template<size_t Size>
std::array<bool, Size> dump_vector_in_array(std::vector<bool> vect);

bits384 get_bits384_from_vector(std::vector<bool> vect);
bits256 get_bits256_from_vector(std::vector<bool> vect);
bits64 get_bits64_from_vector(std::vector<bool> vect);
bits32 get_bits32_from_vector(std::vector<bool> vect);
template<size_t TreeDepth>
bits_addr<TreeDepth> get_bits_addr_from_vector(const std::vector<bool> &vect);

// Dump an array into a vector
template<size_t Size>
std::vector<bool> dump_array_in_vector(std::array<bool, Size> arr);

std::vector<bool> get_vector_from_bits384(bits384 arr);
std::vector<bool> get_vector_from_bits256(bits256 arr);
std::vector<bool> get_vector_from_bits64(bits64 arr);
std::vector<bool> get_vector_from_bits32(bits32 arr);
template<size_t TreeDepth>
std::vector<bool> get_vector_from_bits_addr(const bits_addr<TreeDepth> &arr);

// Sum 2 binary strings
template<size_t BitLen>
std::array<bool, BitLen> binary_addition(
    std::array<bool, BitLen> A,
    std::array<bool, BitLen> B,
    bool withCarry = false);

template<size_t BitLen>
std::array<bool, BitLen> binary_xor(
    std::array<bool, BitLen> A, std::array<bool, BitLen> B);

bits64 sum_bits64(bits64 a, bits64 b);

} // namespace libzeth
#include "bits.tcc"

#endif // __ZETH_TYPES_BITS_HPP__
