// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CORE_BITS_TCC__
#define __ZETH_CORE_BITS_TCC__

#include "libzeth/core/bits.hpp"

#include <limits>
#include <utility>

namespace libzeth
{

uint8_t char_to_nibble(char);

namespace
{

template<size_t Size>
std::vector<bool> array_to_vector(const std::array<bool, Size> &arr)
{
    std::vector<bool> vect(Size);
    std::copy(arr.begin(), arr.end(), vect.begin());
    return vect;
}

} // namespace

template<size_t numBits> bits<numBits>::bits()
{
    for (size_t i = 0; i < numBits; ++i) {
        (*this)[i] = false;
    }
}

template<size_t numBits>
template<typename... boolList>
bits<numBits>::bits(const boolList &...bits)
    : std::array<bool, numBits>{std::forward<bool>(bits)...}
{
}

template<size_t numBits> std::vector<bool> bits<numBits>::to_vector() const
{
    return array_to_vector(*this);
}

template<size_t numBits>
bits<numBits> bits<numBits>::from_vector(const std::vector<bool> &bin)
{
    if (bin.size() != numBits) {
        throw std::invalid_argument("invalid vector size");
    }
    return bits(bin.begin());
}

template<size_t numBits>
bits<numBits> bits<numBits>::from_hex(const std::string &hex)
{
    if (hex.size() != numBits / 4) {
        throw std::invalid_argument("invalid hex string length");
    }
    bits<numBits> result;
    size_t i = 0;
    for (const char c : hex) {
        const uint8_t nibble = char_to_nibble(c);
        result[i++] = (nibble & 8) != 0;
        result[i++] = (nibble & 4) != 0;
        result[i++] = (nibble & 2) != 0;
        result[i++] = (nibble & 1) != 0;
    }

    return result;
}

template<size_t numBits>
bits<numBits> bits<numBits>::from_size_t(size_t address)
{
    // cppcheck-suppress shiftTooManyBits
    // cppcheck-suppress knownConditionTrueFalse
    if ((numBits < 64) && (address >= (1ull << numBits))) {
        throw std::invalid_argument("Address overflow");
    }

    // Initialize one bit at a time, earlying out if address turns to 0. Set
    // all remaining bits to 0.
    bool result[numBits];
    size_t i;
    for (i = 0; i < numBits && address != 0; ++i, address >>= 1) {
        result[i] = address & 0x1;
    }
    for (; i < numBits; ++i) {
        result[i] = 0;
    }

    return bits_addr<numBits>(result);
}

template<size_t numBits> bool bits<numBits>::is_zero() const
{
    return !std::any_of(
        this->begin(), this->end(), [](const bool b) { return b != 0; });
};

template<size_t numBits>
template<typename FieldT>
void bits<numBits>::fill_variable_array(
    libsnark::protoboard<FieldT> &pb,
    libsnark::pb_variable_array<FieldT> &var_array) const
{
    if (var_array.size() != numBits) {
        throw std::invalid_argument("invalid pb_variable_array size");
    }
    for (size_t i = 0; i < numBits; ++i) {
        pb.val(var_array[i]) = ((*this)[i]) ? FieldT::one() : FieldT::zero();
    }
}

template<size_t numBits>
template<typename boolIt>
bits<numBits>::bits(boolIt it)
{
    fill_from_iterator(it);
}

template<size_t numBits>
template<typename boolIt>
void bits<numBits>::fill_from_iterator(boolIt it)
{
    // (Internal function) Caller expected to check that enough elements are
    // present before passing an iterator in.
    for (size_t i = 0; i < numBits; ++i, ++it) {
        (*this)[i] = *it;
    }
}

template<size_t numBits>
bits<numBits> bits_xor(const bits<numBits> &a, const bits<numBits> &b)
{
    bits<numBits> result;
    for (size_t i = 0; i < numBits; ++i) {
        result[i] = a[i] ^ b[i];
    }
    return result;
}

template<size_t numBits>
bits<numBits> bits_add(
    const bits<numBits> &as, const bits<numBits> &bs, bool with_carry)
{
    bits<numBits> result;

    bool carry = false;
    size_t i = numBits;
    while (i > 0) {
        --i;
        // (r, carry) = a + carry,
        // (result[i], carry) = r + b
        const bool a = as[i];
        const bool b = bs[i];
        bool r = a ^ carry;
        carry = carry && a;
        result[i] = r ^ b;
        carry = carry || (r && b);
    }

    // If we ask for the last carry to be taken into account
    // (with_carry=true) and that the last carry is 1, then we raise an
    // overflow error
    if (with_carry && carry) {
        throw std::overflow_error("Overflow: The sum of the binary addition "
                                  "cannot be encoded on <BitLen> bits");
    }

    return result;
}

} // namespace libzeth

#endif // __ZETH_CORE_BITS_TCC__
