// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SERIALIZATION_STREAM_UTILS_HPP__
#define __ZETH_SERIALIZATION_STREAM_UTILS_HPP__

namespace libzeth
{

/// Read a primitive datatype from a stream as raw bytes.
template<typename T>
typename std::enable_if<std::is_fundamental<T>::value, T>::type read_bytes(
    std::istream &in_s);

/// Read a primitive datatype from a stream as raw bytes.
template<typename T>
typename std::enable_if<std::is_fundamental<T>::value, void>::type read_bytes(
    T &val, std::istream &in_s);

// Write a primitive datatype to a stream as raw bytes.ap
template<typename T>
typename std::enable_if<std::is_fundamental<T>::value, void>::type write_bytes(
    const T &val, std::ostream &out_s);

} // namespace libzeth

#include "libzeth/serialization/stream_utils.tcc"

#endif // __ZETH_SERIALIZATION_STREAM_UTILS_HPP__
