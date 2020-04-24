// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_UTIL_TCC__
#define __ZETH_UTIL_TCC__

#include "libzeth/util.hpp"

namespace libzeth
{

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

template<size_t TreeDepth>
std::vector<bool> address_bits_from_address(size_t address)
{
    std::vector<bool> binary = convert_uint_to_binary(address);
    std::vector<bool> result(TreeDepth, 0);

    // Address encoded on more bits that the address space allows
    if (binary.size() > TreeDepth) {
        throw std::invalid_argument("Address overflow");
    }

    // We need to "back pad" the binary conversion we obtained to have an
    // address encoded by a binary string of the length of the tree_depth
    if (binary.size() < TreeDepth) {
        for (size_t i = 0; i < binary.size(); i++) {
            result[i] = binary[i];
        }

        // We return the "back padded" vector
        return result;
    }

    return binary;
}

// template<typename StructuredT>
// void check_well_formed_(const StructuredT &v, const char *name)
// {
//     if (!is_well_formed(v)) {
//         throw std::invalid_argument(std::string(name) + " not well-formed");
//     }
// }

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

#endif // __ZETH_UTIL_TCC__
