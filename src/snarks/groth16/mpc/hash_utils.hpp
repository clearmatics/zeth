// Copyright (c) 2015-2019 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SNARKS_GROTH16_MPC_HASH_UTILS_HPP__
#define __ZETH_SNARKS_GROTH16_MPC_HASH_UTILS_HPP__

#include <ios>
#include <iostream>
#include <sodium/crypto_generichash_blake2b.h>

namespace libzeth
{

// Hashing for MPC. Streaming and whole-buffer interfaces.
const size_t SRS_MPC_HASH_SIZE = 64;
const size_t SRS_MPC_HASH_ARRAY_LENGTH = SRS_MPC_HASH_SIZE / sizeof(size_t);

using srs_mpc_hash_t = size_t[SRS_MPC_HASH_ARRAY_LENGTH];
using srs_mpc_hash_state_t = crypto_generichash_blake2b_state;

void srs_mpc_hash_init(srs_mpc_hash_state_t &);
void srs_mpc_hash_update(srs_mpc_hash_state_t &, const void *, size_t);
void srs_mpc_hash_final(srs_mpc_hash_state_t &, srs_mpc_hash_t);
void srs_mpc_compute_hash(
    srs_mpc_hash_t out_hash, const void *data, size_t data_size);
void srs_mpc_compute_hash(srs_mpc_hash_t out_hash, const std::string &data);

/// Convert a hash to a human-readable string (4 x 4 x 4-byte hex words),
/// following the format used in the "powersoftau" and "Sapling MPC" code.
void srs_mpc_hash_write(const srs_mpc_hash_t hash, std::ostream &out);

/// Parse a human-readable string (4 x 4 x 4-byte hex words) representing an
/// srs_mpc_hash_t.
bool srs_mpc_hash_read(srs_mpc_hash_t out_hash, std::istream &in);

class hash_streambuf : std::streambuf
{
protected:
    hash_streambuf();
    virtual std::streamsize xsputn(const char *s, std::streamsize n) override;

    srs_mpc_hash_state_t hash_state;

    friend class hash_ostream;
};

class hash_streambuf_wrapper : std::streambuf
{
protected:
    hash_streambuf_wrapper(std::ostream *inner);
    hash_streambuf_wrapper(std::istream *inner);
    virtual std::streamsize xsputn(const char *s, std::streamsize n) override;
    virtual std::streamsize xsgetn(char *s, std::streamsize n) override;

    std::ostream *inner_out;
    std::istream *inner_in;
    srs_mpc_hash_state_t hash_state;

    friend class hash_ostream_wrapper;
    friend class hash_istream_wrapper;
};

class hash_ostream : public std::ostream
{
public:
    hash_ostream();
    void get_hash(srs_mpc_hash_t out_hash);

private:
    hash_streambuf hsb;
};

class hash_ostream_wrapper : public std::ostream
{
public:
    hash_ostream_wrapper(std::ostream &inner_stream);
    void get_hash(srs_mpc_hash_t out_hash);

private:
    hash_streambuf_wrapper hsb;
};

class hash_istream_wrapper : public std::istream
{
public:
    hash_istream_wrapper(std::istream &inner_stream);
    void get_hash(srs_mpc_hash_t out_hash);

private:
    hash_streambuf_wrapper hsb;
};

} // namespace libzeth

#endif // __ZETH_SNARKS_GROTH16_MPC_HASH_UTILS_HPP__
