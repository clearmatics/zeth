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

template<typename T, void(ReaderFn)(T &, std::istream &)>
void sparse_vector_read_bytes(
    libsnark::sparse_vector<T> &sparse_vector, std::istream &in_s)
{
    sparse_vector.domain_size_ = read_bytes<size_t>(in_s);
    const size_t num_entries = read_bytes<size_t>(in_s);
    sparse_vector.indices.clear();
    sparse_vector.indices.reserve(num_entries);
    sparse_vector.values.clear();
    sparse_vector.values.reserve(num_entries);

    for (size_t i = 0; i < num_entries; ++i) {
        sparse_vector.indices.push_back(read_bytes<size_t>(in_s));
        sparse_vector.values.emplace_back();
        ReaderFn(sparse_vector.values.back(), in_s);
    }
}

template<typename T, void(WriterFn)(const T &, std::ostream &)>
void sparse_vector_write_bytes(
    const libsnark::sparse_vector<T> &sparse_vector, std::ostream &out_s)
{
    const size_t num_entries = sparse_vector.indices.size();
    assert(num_entries == sparse_vector.values.size());

    write_bytes(sparse_vector.domain_size_, out_s);
    write_bytes(num_entries, out_s);
    for (size_t i = 0; i < num_entries; ++i) {
        write_bytes(sparse_vector.indices[i], out_s);
        WriterFn(sparse_vector.values[i], out_s);
    }
}

template<typename T, void(ReaderFn)(T &, std::istream &)>
void accumulation_vector_read_bytes(
    libsnark::accumulation_vector<T> &acc_vector, std::istream &in_s)
{
    // const size_t num_elements = read_bytes<size_t>(in_s);
    // assert(num_elements > 0);
    // group_element_read_bytes(acc_vector.first);
    // acc_vector.rest.clear();
    // acc_vector.rest.reserve();

    // acc_vector.

    ReaderFn(acc_vector.first, in_s);
    sparse_vector_read_bytes<T, ReaderFn>(acc_vector.rest, in_s);
}

template<typename T, void(WriterFn)(const T &, std::ostream &)>
void accumulation_vector_write_bytes(
    const libsnark::accumulation_vector<T> &acc_vector, std::ostream &out_s)
{
    WriterFn(acc_vector.first, out_s);
    sparse_vector_write_bytes<T, WriterFn>(acc_vector.rest, out_s);
}

} // namespace libzeth

#endif // __ZETH_SERIALIZATION_STREAM_UTILS_TCC__
