// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CIRCUITS_SAFE_ARITHMETIC_HPP__
#define __ZETH_CIRCUITS_SAFE_ARITHMETIC_HPP__

#include <cstddef>

namespace libzeth
{

/// Subtract `b` from `a`, clamping the result to [0, a] (i.e. returns `0` if
/// `b > a` instead of wrapping around to the top of the range of values).
size_t subtract_with_clamp(size_t a, size_t b);

} // namespace libzeth

#endif // __ZETH_CIRCUITS_SAFE_ARITHMETIC_HPP__
