// Copyright (c) 2015-2019 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "circuits-utils.hpp"

namespace libzeth
{

void insert_bits256(std::vector<bool> &into, bits256 from)
{
    std::vector<bool> blob = get_vector_from_bits256(from);
    into.insert(into.end(), blob.begin(), blob.end());
};

void insert_bits64(std::vector<bool> &into, bits64 from)
{
    std::vector<bool> num = get_vector_from_bits64(from);
    into.insert(into.end(), num.begin(), num.end());
};

std::vector<unsigned long> bit_list_to_ints(
    std::vector<bool> bit_list, const size_t wordsize)
{
    std::vector<unsigned long> res;
    size_t iterations = bit_list.size() / wordsize + 1;
    for (size_t i = 0; i < iterations; ++i) {
        unsigned long current = 0;
        for (size_t j = 0; j < wordsize; ++j) {
            if (bit_list.size() == (i * wordsize + j))
                break;
            current +=
                (bit_list[i * wordsize + j] * (1ul << (wordsize - 1 - j)));
        }
        res.push_back(current);
    }
    return res;
}

std::vector<bool> convert_to_binary(size_t n)
{
    std::vector<bool> res;

    if (n / 2 != 0) {
        std::vector<bool> temp = convert_to_binary(n / 2);
        res.insert(res.end(), temp.begin(), temp.end());
    }

    if (n % 2 == 1) {
        res.push_back(1);
    } else {
        res.push_back(0);
    }

    return res;
}

} // namespace libzeth
