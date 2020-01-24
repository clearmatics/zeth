// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/circuits/circuits_utils.hpp"

namespace libzeth
{

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