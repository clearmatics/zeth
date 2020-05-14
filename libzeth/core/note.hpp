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

    zeth_note(bits256 a_pk, bits64 value, bits256 rho, bits256 r)
        : a_pk(a_pk), value(value), rho(rho), r(r)
    {
    }

    zeth_note() { value.fill(false); }

    inline bool is_zero_valued() const
    {
        return !std::any_of(
            value.begin(), value.end(), [](const bool b) { return b; });
    }
};

} // namespace libzeth

#endif // __ZETH_CORE_NOTE_HPP__
