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
