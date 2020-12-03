// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CORE_UTILS_TCC__
#define __ZETH_CORE_UTILS_TCC__

#include "libzeth/core/utils.hpp"

#include <cmath>
#include <stdexcept> // required for std::length_error on linux

namespace libzeth
{

template<> constexpr size_t bit_utils<0>::bit_size() { return 0; }

template<> constexpr size_t bit_utils<0>::num_true_bits() { return 0; }

template<size_t X> constexpr size_t bit_utils<X>::bit_size()
{
    return 1 + bit_utils<(X >> 1)>::bit_size();
}

template<size_t X> constexpr size_t bit_utils<X>::num_true_bits()
{
    return (X & 1) + bit_utils<(X >> 1)>::bit_size();
}

template<typename T> T swap_byte_endianness(T v)
{
    size_t len = v.size();
    if (len == 0) {
        throw std::length_error(
            "Invalid bit length for the given boolean vector (should be > 0)");
    }
    if (len % 8 != 0) {
        throw std::length_error("Invalid bit length for the given boolean "
                                "vector (should be multiple of 8)");
    }

    size_t byte_mid_length = std::ceil((len / 8) / 2);
    for (size_t i = 0; i < byte_mid_length; i++) {
        for (size_t j = 0; j < 8; j++) {
            std::swap(v[8 * i + j], v[len - 8 * (i + 1) + j]);
        }
    }
    return v;
}

template<typename StructuredTs>
bool container_is_well_formed(const StructuredTs &values)
{
    for (const auto &v : values) {
        if (!v.is_well_formed()) {
            return false;
        }
    }

    return true;
}

template<typename StructuredT>
void check_well_formed(const StructuredT &v, const char *name)
{
    if (!v.is_well_formed()) {
        throw std::invalid_argument(std::string(name) + " not well-formed");
    }
}

} // namespace libzeth

#endif // __ZETH_CORE_UTILS_TCC__
