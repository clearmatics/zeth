// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SERIALIZATION_STREAM_UTILS_HPP__
#define __ZETH_SERIALIZATION_STREAM_UTILS_HPP__

#include <iostream>
#include <type_traits>

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

/// Write the first n from a collection of values, using a specified writer
/// function.
template<
    typename ValueT,
    typename CollectionT,
    void(WriterT)(const ValueT &, std::ostream &)>
void collection_n_write_bytes(
    const CollectionT &collection, const size_t n, std::ostream &out_s);

/// Read n element using a specified reader function, appending to the given
/// collection.
template<
    typename ValueT,
    typename CollectionT,
    void(ReaderT)(ValueT &, std::istream &)>
void collection_n_read_bytes_n(
    CollectionT &collection, const size_t n, std::istream &in_s);

/// Write a full collection of group elements to a stream as bytes, using
/// a specific writer function.
template<
    typename ValueT,
    typename CollectionT,
    void(WriterT)(const ValueT &, std::ostream &)>
void collection_write_bytes(const CollectionT &collection, std::ostream &out_s);

/// Read a collection of group elements as bytes, usinng
/// group_elements_read_bytes.
template<
    typename ValueT,
    typename CollectionT,
    void(ReaderT)(ValueT &, std::istream &)>
void collection_read_bytes(CollectionT &points, std::istream &in_s);

} // namespace libzeth

#include "libzeth/serialization/stream_utils.tcc"

#endif // __ZETH_SERIALIZATION_STREAM_UTILS_HPP__
