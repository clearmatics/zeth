// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CORE_BITS_HPP__
#define __ZETH_CORE_BITS_HPP__

#include "libzeth/core/include_libsnark.hpp"

#include <array>
#include <iostream>
#include <stddef.h>
#include <vector>

namespace libzeth
{

// Forward declarations
template<size_t numBits> class bits;

/// XOR two binary strings of the same length.
template<size_t numBits>
bits<numBits> bits_xor(const bits<numBits> &a, const bits<numBits> &b);

/// Sum 2 binary strings with or without carry
template<size_t numBits>
bits<numBits> bits_add(
    const bits<numBits> &a, const bits<numBits> &b, bool with_carry = false);

/// Generic class representing a bit-array of a specific size.
template<size_t numBits> class bits : public std::array<bool, numBits>
{
public:
    bits();

    /// Construct from initializer-list.
    // cppcheck-suppress noExplicitConstructor
    template<typename... boolList> bits(const boolList &... bits);

    std::vector<bool> to_vector() const;

    static bits from_vector(const std::vector<bool> &bin);

    static bits from_hex(const std::string &hex);

    /// Create a bits object from a size_t, specifically for bits_addr type.
    /// Only available for TreeDepth small enough that TreeDepth bits can be
    /// expressed in size_t.
    static bits from_size_t(size_t addr);

    bool is_zero() const;

    /// Fill a libsnark::pb_variable_array with bits from this container,
    /// representing each as 1 or 0 in FieldT.
    template<typename FieldT>
    void fill_variable_array(
        libsnark::protoboard<FieldT> &pb,
        libsnark::pb_variable_array<FieldT> &var_array) const;

protected:
    template<typename boolIt> explicit bits(boolIt it);
    template<typename boolIt> void fill_from_iterator(boolIt it);

    friend bits bits_xor<numBits>(const bits &, const bits &);
    friend bits bits_add<numBits>(const bits &, const bits &, bool);
};

/// 32-bit array
using bits32 = bits<32>;

/// 64-bit array
using bits64 = bits<64>;

// 256-bit array t
using bits256 = bits<256>;

using bits384 = bits<384>;

template<size_t TreeDepth> using bits_addr = bits<TreeDepth>;

/// Takes a hexadecimal string and converts it into a bit-vector. Throws an
/// exception if called with an invalid hexadecimal string.
std::vector<bool> bit_vector_from_hex(const std::string &str);

/// Returns the little endian binary encoding of the integer x.
std::vector<bool> bit_vector_from_size_t_le(size_t x);

/// Returns the big endian binary encoding of the integer x.
std::vector<bool> bit_vector_from_size_t_be(size_t x);

} // namespace libzeth

#include "libzeth/core/bits.tcc"

#endif // __ZETH_CORE_BITS_HPP__
