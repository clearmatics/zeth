// Copyright (c) 2015-2019 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_UTIL_TCC__
#define __ZETH_UTIL_TCC__

#include "util.hpp"

namespace libzeth
{

// Takes a containers with a size method and reverse the elements' order
// The elements should represent bits
template<typename T> T swap_bit_endianness(T v)
{
    size_t len = v.size();
    if (len == 0) {
        throw std::length_error(
            "Invalid bit length for the given boolean vector (should be > 0)");
    }

    for (size_t i = 0; i < len / 2; i++) {
        std::swap(v[i], v[(len - 1) - i]);
    }
    return v;
}

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

// string_to_field(std::string input) converts a string ob bytes of size <=32 to
// a FieldT element.
template<typename FieldT> FieldT string_to_field(std::string input)
{
    int input_len = input.length();

    // Sanity checks
    // length
    if (input_len == 0 || input.length() > 64) {
        throw std::length_error(
            "Invalid byte string length for the given field string");
    }

    // Copy the string into a char array
    char char_array[input.length() + 1];
    strcpy(char_array, input.c_str());

    // Construct gmp integer from the string
    mpz_t n;
    mpz_init(n);

    int flag = mpz_set_str(n, char_array, 16);
    if (flag != 0) {
        throw std::runtime_error(std::string("Invalid hex string"));
    };

    // Construct libff::bigint from gmp integer
    libff::bigint<4> n_big_int = libff::bigint<4>(n);

    // Construct field element from a bigint
    FieldT element = FieldT(n_big_int);
    return element;
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
