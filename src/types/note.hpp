// Copyright (c) 2015-2019 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_TYPES_NOTE_HPP__
#define __ZETH_TYPES_NOTE_HPP__

#include "types/bits.hpp"

#include <array>

namespace libzeth
{

class base_note
{
protected:
    bits64 value_;

public:
    base_note() { value_.fill(false); }
    base_note(bits64 value) : value_(value){};
    virtual ~base_note(){};

    inline bits64 value() const { return value_; };

    // Test if the note is a 0-valued note
    inline bool is_zero_valued() const
    {
        bits64 zero;
        zero.fill(false);
        return value_ == zero;
    }
};

class zeth_note : public base_note
{
public:
    bits256 a_pk; // 256-bit vector
    bits256 rho;  // 256-bit vector
    bits384 r;    // 384-bit random vector
    // bits256 cm; // 256-bit vector

    zeth_note(
        bits256 a_pk, bits64 value, bits256 rho, bits384 r /*, bits256 cm*/)
        : base_note(value), a_pk(a_pk), rho(rho), r(r) /*, cm(cm)*/
    {
    }

    zeth_note(){};
    virtual ~zeth_note(){};
};

} // namespace libzeth

#endif // __ZETH_TYPES_NOTE_HPP__