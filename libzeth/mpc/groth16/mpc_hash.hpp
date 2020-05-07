// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_MPC_GROTH16_MPC_HASH_HPP__
#define __ZETH_MPC_GROTH16_MPC_HASH_HPP__

#include "libzeth/core/hash_stream.hpp"

#include <sodium/crypto_generichash_blake2b.h>
#include <string>

namespace libzeth
{

// Hashing for MPC. Streaming and whole-buffer interfaces.
static const size_t MPC_HASH_SIZE_BYTES = 64;
static const size_t MPC_HASH_ARRAY_LENGTH =
    MPC_HASH_SIZE_BYTES / sizeof(size_t);

using mpc_hash_t = size_t[MPC_HASH_ARRAY_LENGTH];
using mpc_hash_state_t = crypto_generichash_blake2b_state;

void mpc_hash_init(mpc_hash_state_t &);
void mpc_hash_update(mpc_hash_state_t &, const void *, size_t);
void mpc_hash_final(mpc_hash_state_t &, mpc_hash_t);
void mpc_compute_hash(mpc_hash_t out_hash, const void *data, size_t data_size);
void mpc_compute_hash(mpc_hash_t out_hash, const std::string &data);

/// Convert a hash to a human-readable string (4 x 4 x 4-byte hex words),
/// following the format used in the "powersoftau" and "Sapling MPC" code.
void mpc_hash_write(const mpc_hash_t hash, std::ostream &out);

/// Parse a human-readable string (4 x 4 x 4-byte hex words) representing an
/// mpc_hash_t.
bool mpc_hash_read(mpc_hash_t out_hash, std::istream &in);

/// Simple class wrapper around the above hash, following the HashT interface
/// in hash_stream.hpp.
class mpc_hash
{
private:
    mpc_hash_state_t state;

public:
    using OutBuffer = mpc_hash_t;

    mpc_hash();
    void update(const void *, size_t);
    void final(OutBuffer out_buffer);
};

using mpc_hash_ostream = hash_ostream<mpc_hash>;
using mpc_hash_ostream_wrapper = hash_ostream_wrapper<mpc_hash>;
using mpc_hash_istream_wrapper = hash_istream_wrapper<mpc_hash>;

} // namespace libzeth

#endif // __ZETH_MPC_GROTH16_MPC_HASH_HPP__
