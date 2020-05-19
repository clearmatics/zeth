// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CORE_NOTE_HPP__
#define __ZETH_CORE_NOTE_HPP__

#include "libzeth/core/bits.hpp"

#include <array>

namespace libzeth
{

class zeth_note
{
public:
    bits256 a_pk;
    bits64 value;
    bits256 rho;
    bits256 r;

    // Note, r-value refs are not used because the bits* objects are all
    // trivially-copyable.
    zeth_note(
        const bits256 &a_pk,
        const bits64 &value,
        const bits256 &rho,
        const bits256 &r)
        : a_pk(a_pk), value(value), rho(rho), r(r)
    {
    }

    zeth_note() {}

    inline bool is_zero_valued() const { return value.is_zero(); }
};

} // namespace libzeth

#endif // __ZETH_CORE_NOTE_HPP__
