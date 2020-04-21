// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_UTIL_TCC__
#define __ZETH_UTIL_TCC__

#include "libzeth/util.hpp"

namespace libzeth
{

// Takes a containers with a size method and reverse the elements' order
// The elements should represent bits
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

    if (binary.size() > TreeDepth) {
        // Address encoded on more bits that the address space allows
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

/// Function that converts an hexadecimal string into a field element.
/// This function throws a `invalid_argument` exception if the conversion fails.
template<typename FieldT>
FieldT hexadecimal_str_to_field_element(std::string field_str)
{
    // Remove prefix if any
    erase_substring(field_str, std::string("0x"));

    // 1 byte will be populated by 2 hexadecimal characters
    uint8_t val[field_str.size() / 2];

    char cstr[field_str.size() + 1];
    strcpy(cstr, field_str.c_str());

    int res = hexadecimal_str_to_binary(cstr, val);
    if (res == 0) {
        throw std::invalid_argument("Invalid hexadecimal string");
    }

    libff::bigint<FieldT::num_limbs> el =
        libsnark_bigint_from_bytes<FieldT>(val);
    return FieldT(el);
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

template<typename StructuredT>
void check_well_formed_(const StructuredT &v, const char *name)
{
    if (!is_well_formed(v)) {
        throw std::invalid_argument(std::string(name) + " not well-formed");
    }
}

} // namespace libzeth

#endif // __ZETH_UTIL_TCC__
