// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CORE_HASH_STREAM_TCC__
#define __ZETH_CORE_HASH_STREAM_TCC__

#include "libzeth/core/hash_stream.hpp"

namespace libzeth
{

template<typename HashT> hash_streambuf<HashT>::hash_streambuf() : hash_state()
{
}

template<typename HashT>
std::streamsize hash_streambuf<HashT>::xsputn(const char *s, std::streamsize n)
{
    hash_state.update(s, n);
    return n;
}

template<typename HashT>
hash_streambuf_wrapper<HashT>::hash_streambuf_wrapper(std::ostream *inner)
    : hash_state(), inner_out(inner), inner_in(nullptr)
{
}

template<typename HashT>
hash_streambuf_wrapper<HashT>::hash_streambuf_wrapper(std::istream *inner)
    : hash_state(), inner_out(nullptr), inner_in(inner)
{
}

template<typename HashT>
std::streamsize hash_streambuf_wrapper<HashT>::xsputn(
    const char *s, std::streamsize n)
{
    inner_out->write(s, n);
    hash_state.update(s, n);
    return n;
}

template<typename HashT>
std::streamsize hash_streambuf_wrapper<HashT>::xsgetn(
    char *s, std::streamsize n)
{
    inner_in->read(s, n);
    hash_state.update(s, n);
    return n;
}

template<typename HashT>
hash_ostream<HashT>::hash_ostream() : std::ostream(&hsb), hsb()
{
}

template<typename HashT>
void hash_ostream<HashT>::get_hash(typename HashT::OutBuffer out_hash)
{
    hsb.hash_state.final(out_hash);
}

template<typename HashT>
hash_ostream_wrapper<HashT>::hash_ostream_wrapper(std::ostream &inner_stream)
    : std::ostream(&hsb), hsb(&inner_stream)
{
}

template<typename HashT>
void hash_ostream_wrapper<HashT>::get_hash(typename HashT::OutBuffer out_hash)
{
    hsb.hash_state.final(out_hash);
}

template<typename HashT>
hash_istream_wrapper<HashT>::hash_istream_wrapper(std::istream &inner_stream)
    : std::istream(&hsb), hsb(&inner_stream)
{
}

template<typename HashT>
void hash_istream_wrapper<HashT>::get_hash(typename HashT::OutBuffer out_hash)
{
    hsb.hash_state.final(out_hash);
}

} // namespace libzeth

#endif // __ZETH_CORE_HASH_STREAM_TCC__
