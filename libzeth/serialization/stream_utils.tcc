// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SERIALIZATION_STREAM_UTILS_TCC__
#define __ZETH_SERIALIZATION_STREAM_UTILS_TCC__

#include "libzeth/serialization/stream_utils.hpp"

namespace libzeth
{

template<typename T>
typename std::enable_if<std::is_fundamental<T>::value, T>::type read_bytes(
    std::istream &in_s)
{
    T val;
    read_bytes(val, in_s);
    return val;
}

template<typename T>
typename std::enable_if<std::is_fundamental<T>::value, void>::type read_bytes(
    T &val, std::istream &in_s)
{
    in_s.read((char *)(&val), sizeof(T));
}

template<typename T>
typename std::enable_if<std::is_fundamental<T>::value, void>::type write_bytes(
    const T &val, std::ostream &out_s)
{
    out_s.write((const char *)(&val), sizeof(T));
}

} // namespace libzeth

#endif // __ZETH_SERIALIZATION_STREAM_UTILS_TCC__
