// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/circuits/safe_arithmetic.hpp"

namespace libzeth
{

std::size_t subtract_with_clamp(std::size_t a, std::size_t b)
{
    if (b > a) {
        return 0;
    }
    return a - b;
};

} // namespace libzeth
