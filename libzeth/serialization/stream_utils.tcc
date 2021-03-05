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

/// Write the first n from a collection of values, using a specified writer
/// function.
template<
    typename ValueT,
    typename CollectionT,
    void(WriterFn)(const ValueT &, std::ostream &)>
void collection_n_write_bytes(
    const CollectionT &collection, const size_t n, std::ostream &out_s)
{
    for (size_t i = 0; i < n; ++i) {
        WriterFn(collection[i], out_s);
    }
}

/// Read n element using a specified reader function, appending to the given
/// collection.
template<
    typename ValueT,
    typename CollectionT,
    void(ReaderFn)(ValueT &, std::istream &)>
void collection_n_read_bytes(
    CollectionT &collection, const size_t n, std::istream &in_s)
{
    for (size_t i = 0; i < n; ++i) {
        collection.emplace_back();
        ReaderFn(collection.back(), in_s);
    }
}

/// Write a full collection of values to a stream as bytes, using
/// a specific writer function.
template<
    typename ValueT,
    typename CollectionT,
    void(WriterT)(const ValueT &, std::ostream &)>
void collection_write_bytes(const CollectionT &collection, std::ostream &out_s)
{
    write_bytes(collection.size(), out_s);
    collection_n_write_bytes<ValueT, CollectionT, WriterT>(
        collection, collection.size(), out_s);
}

/// Read a collection of values, from a stream of bytes, using
/// a specific reader function.
template<
    typename ValueT,
    typename CollectionT,
    void(ReaderT)(ValueT &, std::istream &)>
void collection_read_bytes(CollectionT &collection, std::istream &in_s)
{
    const size_t n = read_bytes<size_t>(in_s);

    collection.clear();
    collection.reserve(n);
    collection_n_read_bytes<ValueT, CollectionT, ReaderT>(collection, n, in_s);
}

} // namespace libzeth

#endif // __ZETH_SERIALIZATION_STREAM_UTILS_TCC__
