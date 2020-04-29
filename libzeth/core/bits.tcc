// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CORE_BITS_TCC__
#define __ZETH_CORE_BITS_TCC__

#include "libzeth/core/bits.hpp"

namespace libzeth
{

namespace
{

template<size_t Size>
std::vector<bool> array_to_vector(const std::array<bool, Size> &arr)
{
    std::vector<bool> vect(Size);
    std::copy(arr.begin(), arr.end(), vect.begin());
    return vect;
}

template<size_t Size>
std::array<bool, Size> vector_to_array(const std::vector<bool> &vect)
{
    std::array<bool, Size> array;
    if (vect.size() != Size) {
        throw std::length_error(
            "Invalid bit length for the given boolean vector (should be equal "
            "to the size of the vector)");
    }

    std::copy(vect.begin(), vect.end(), array.begin());
    return array;
}

} // namespace

template<size_t TreeDepth>
bits_addr<TreeDepth> bits_addr_from_vector(const std::vector<bool> &vect)
{
    return vector_to_array<TreeDepth>(vect);
}

template<size_t TreeDepth>
std::vector<bool> bits_addr_to_vector(const bits_addr<TreeDepth> &arr)
{
    return array_to_vector<TreeDepth>(arr);
}

template<size_t TreeDepth>
bits_addr<TreeDepth> bits_addr_from_size_t(size_t address)
{
    if (address >= (1ull << TreeDepth)) {
        throw std::invalid_argument("Address overflow");
    }

    // Fill with zeroes and fill one bit at a time. Early out if address turns
    // to 0.
    bits_addr<TreeDepth> result;
    result.fill(0);
    for (size_t i = 0; i < TreeDepth && address != 0; ++i, address >>= 1) {
        result[i] = address & 0x1;
    }
    return result;
}

template<size_t BitLen>
std::array<bool, BitLen> bits_xor(
    const std::array<bool, BitLen> &a, const std::array<bool, BitLen> &b)
{
    std::array<bool, BitLen> xor_array;
    xor_array.fill(0);

    for (int i = BitLen - 1; i >= 0; i--) {
        xor_array[i] = a[i] != b[i];
    }

    return xor_array;
}

template<size_t BitLen>
std::array<bool, BitLen> bits_add(
    const std::array<bool, BitLen> &a,
    const std::array<bool, BitLen> &b,
    bool with_carry)
{
    std::array<bool, BitLen> sum;
    sum.fill(0);

    bool carry = 0;
    for (int i = BitLen - 1; i >= 0; i--) {
        sum[i] = ((a[i] ^ b[i]) ^ carry);
        carry = ((a[i] & b[i]) | (a[i] & carry)) | (b[i] & carry);
    }

    // If we ask for the last carry to be taken into account (with_carry=true)
    // and that the last carry is 1, then we raise an overflow error
    if (with_carry && carry) {
        throw std::overflow_error("Overflow: The sum of the binary addition "
                                  "cannot be encoded on <BitLen> bits");
    }

    return sum;
}

} // namespace libzeth

#endif // __ZETH_CORE_BITS_TCC__
