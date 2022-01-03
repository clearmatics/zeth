// Copyright (c) 2015-2022 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SERIALIZATION_STREAM_UTILS_HPP__
#define __ZETH_SERIALIZATION_STREAM_UTILS_HPP__

#include "libzeth/core/include_libsnark.hpp"

#include <iostream>
#include <type_traits>

namespace libzeth
{

/// Statically derive the type of the element contained in a (vector-like)
/// collection.
template<typename CollectionT>
using MemberT =
    typename std::decay<decltype((*(CollectionT *)nullptr)[0])>::type;

/// Read a primitive datatype from a stream as raw bytes.
template<typename T>
typename std::enable_if<std::is_fundamental<T>::value, T>::type read_bytes(
    std::istream &in_s);

/// Read a primitive datatype from a stream as raw bytes.
template<typename T>
typename std::enable_if<std::is_fundamental<T>::value, void>::type read_bytes(
    T &val, std::istream &in_s);

// Write a primitive datatype to a stream as raw bytes.
template<typename T>
typename std::enable_if<std::is_fundamental<T>::value, void>::type write_bytes(
    const T &val, std::ostream &out_s);

/// Write the first n from a collection of values, using a specified writer
/// function.
template<
    typename CollectionT,
    void(WriterT)(const MemberT<CollectionT> &, std::ostream &)>
void collection_n_write_bytes(
    const CollectionT &collection, const size_t n, std::ostream &out_s);

/// Read n element using a specified reader function, appending to the given
/// collection.
template<
    typename CollectionT,
    void(ReaderT)(MemberT<CollectionT> &, std::istream &)>
void collection_n_read_bytes_n(
    CollectionT &collection, const size_t n, std::istream &in_s);

/// Write a full collection of group elements to a stream as bytes, using
/// a specific writer function.
template<
    typename CollectionT,
    void(WriterT)(const MemberT<CollectionT> &, std::ostream &)>
void collection_write_bytes(const CollectionT &collection, std::ostream &out_s);

/// Read a collection of group elements as bytes, using
/// group_elements_read_bytes.
template<
    typename CollectionT,
    void(ReaderT)(MemberT<CollectionT> &, std::istream &)>
void collection_read_bytes(CollectionT &points, std::istream &in_s);

template<typename T, void(ReaderFn)(T &, std::istream &)>
void sparse_vector_read_bytes(
    libsnark::sparse_vector<T> &sparse_vector, std::istream &in_s);

template<typename T, void(WriterFn)(const T &, std::ostream &)>
void sparse_vector_write_bytes(
    const libsnark::sparse_vector<T> &sparse_vector, std::ostream &out_s);

template<typename T, void(ReaderFn)(T &, std::istream &)>
void accumulation_vector_read_bytes(
    libsnark::accumulation_vector<T> &acc_vector, std::istream &in_s);

template<typename T, void(WriterFn)(const T &, std::ostream &)>
void accumulation_vector_write_bytes(
    const libsnark::accumulation_vector<T> &acc_vector, std::ostream &out_s);

template<typename kcT>
void knowledge_commitment_read_bytes(
    kcT &knowledge_commitment, std::istream &in_s);

template<typename kcT>
void knowledge_commitment_write_bytes(
    const kcT &knowledge_commitment, std::ostream &out_s);

template<typename kcvectorT>
void knowledge_commitment_vector_read_bytes(
    kcvectorT &knowledge_commitment, std::istream &in_s);

template<typename kcvectorT>
void knowledge_commitment_vector_write_bytes(
    const kcvectorT &knowledge_commitment, std::ostream &out_s);

} // namespace libzeth

#include "libzeth/serialization/stream_utils.tcc"

#endif // __ZETH_SERIALIZATION_STREAM_UTILS_HPP__
