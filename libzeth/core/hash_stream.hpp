// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CORE_HASH_STREAM_HPP__
#define __ZETH_CORE_HASH_STREAM_HPP__

#include <ios>
#include <iostream>

namespace libzeth
{

/// HashT is a class with interface
///
///   class hash
///   {
///   public:
///     typedef OutBuffer;
///     hash();
///     void update(const void *, size_t);
///     void final(OutBuffer out_hash);
///   };
///
/// OutBuffer should be some array type such as size_t[N], so that it can be
/// stack-allocated, and passed as a pointer to the get_hash methods below.

// Forward declare the main public classes in order to declare them as friends
// of the internal classes.
template<typename HashT> class hash_ostream;
template<typename HashT> class hash_ostream_wrapper;
template<typename HashT> class hash_istream_wrapper;

// Internal streambuf for hash_ostream. Hash and discard all written data.
template<typename HashT> class hash_streambuf : std::streambuf
{
protected:
    hash_streambuf();
    virtual std::streamsize xsputn(const char *s, std::streamsize n) override;

    HashT hash_state;

    friend class hash_ostream<HashT>;
};

// Internal streambuf for wrapped streams. Hash data and forward.
template<typename HashT> class hash_streambuf_wrapper : std::streambuf
{
protected:
    hash_streambuf_wrapper(std::ostream *inner);
    hash_streambuf_wrapper(std::istream *inner);
    virtual std::streamsize xsputn(const char *s, std::streamsize n) override;
    virtual std::streamsize xsgetn(char *s, std::streamsize n) override;

    HashT hash_state;
    std::ostream *inner_out;
    std::istream *inner_in;

    friend class hash_ostream_wrapper<HashT>;
    friend class hash_istream_wrapper<HashT>;
};

/// Simple ostream which hashes any incoming data and discards it.
template<typename HashT> class hash_ostream : public std::ostream
{
public:
    hash_ostream();
    void get_hash(typename HashT::OutBuffer out_hash);

private:
    hash_streambuf<HashT> hsb;
};

/// Wrap some ostream, hashing data as it is written.
template<typename HashT> class hash_ostream_wrapper : public std::ostream
{
public:
    hash_ostream_wrapper(std::ostream &inner_stream);
    void get_hash(typename HashT::OutBuffer out_hash);

private:
    hash_streambuf_wrapper<HashT> hsb;
};

/// Wrap some istream, hashing all data as it is read.
template<typename HashT> class hash_istream_wrapper : public std::istream
{
public:
    hash_istream_wrapper(std::istream &inner_stream);
    void get_hash(typename HashT::OutBuffer out_hash);

private:
    hash_streambuf_wrapper<HashT> hsb;
};

} // namespace libzeth

#include "libzeth/core/hash_stream.tcc"

#endif // __ZETH_CORE_HASH_STREAM_HPP__
