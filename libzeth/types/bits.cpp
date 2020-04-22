// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/types/bits.hpp"

namespace libzeth
{

bits384 get_bits384_from_vector(std::vector<bool> vect)
{
    return dump_vector_in_array<384>(vect);
}

bits256 get_bits256_from_vector(std::vector<bool> vect)
{
    return dump_vector_in_array<256>(vect);
}

bits64 get_bits64_from_vector(std::vector<bool> vect)
{
    return dump_vector_in_array<64>(vect);
}

bits384 get_bits384_from_hexadecimal_str(std::string str)
{
    if (str.length() != 96) {
        throw std::length_error(
            "Invalid string length for the given hex digest (should be "
            "96)");
    }

    return get_bits384_from_vector(hexadecimal_str_to_binary_vector(str));
}

bits256 get_bits256_from_hexadecimal_str(std::string str)
{
    if (str.length() != 64) {
        throw std::length_error(
            "Invalid string length for the given hex digest (should be "
            "64)");
    }

    return get_bits256_from_vector(hexadecimal_str_to_binary_vector(str));
}

bits64 get_bits64_from_hexadecimal_str(std::string str)
{
    if (str.length() != 16) {
        throw std::length_error(
            "Invalid string length for the given hex digest (should be "
            "16)");
    }

    return get_bits64_from_vector(hexadecimal_str_to_binary_vector(str));
}

std::vector<bool> get_vector_from_bits384(bits384 arr)
{
    return dump_array_in_vector<384>(arr);
}

std::vector<bool> get_vector_from_bits256(bits256 arr)
{
    return dump_array_in_vector<256>(arr);
}

std::vector<bool> get_vector_from_bits64(bits64 arr)
{
    return dump_array_in_vector<64>(arr);
}

std::vector<bool> get_vector_from_bits32(bits32 arr)
{
    return dump_array_in_vector<32>(arr);
}

} // namespace libzeth
