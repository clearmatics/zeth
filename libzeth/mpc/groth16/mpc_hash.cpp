// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/mpc/groth16/mpc_hash.hpp"

#include "libzeth/core/utils.hpp"

namespace libzeth
{

// In the text representation, use 16 x 4-byte words, (each representated as 8
// digits + separator).
using hash_repr_word = uint32_t;
const size_t hash_repr_word_size = sizeof(hash_repr_word);
const size_t hash_repr_words_per_hash =
    MPC_HASH_SIZE_BYTES / hash_repr_word_size;

static_assert(MPC_HASH_SIZE_BYTES % sizeof(size_t) == 0, "invalid hash size");
static_assert(
    MPC_HASH_SIZE_BYTES == crypto_generichash_blake2b_BYTES_MAX,
    "unexpected hash size");

void mpc_hash_init(mpc_hash_state_t &state)
{
    crypto_generichash_blake2b_init(&state, nullptr, 0, MPC_HASH_SIZE_BYTES);
}

void mpc_hash_update(mpc_hash_state_t &state, const void *in, size_t size)
{
    crypto_generichash_blake2b_update(&state, (const uint8_t *)in, size);
}

void mpc_hash_final(mpc_hash_state_t &state, mpc_hash_t out_hash)
{
    crypto_generichash_blake2b_final(
        &state, (uint8_t *)out_hash, MPC_HASH_SIZE_BYTES);
}

void mpc_compute_hash(mpc_hash_t out_hash, const void *data, size_t data_size)
{
    mpc_hash_state_t s;
    mpc_hash_init(s);
    mpc_hash_update(s, data, data_size);
    mpc_hash_final(s, out_hash);
}

void mpc_compute_hash(mpc_hash_t out_hash, const std::string &data)
{
    mpc_compute_hash(out_hash, data.data(), data.size());
}

void mpc_hash_write(const mpc_hash_t hash, std::ostream &out)
{
    const hash_repr_word *words = (const hash_repr_word *)hash;

    for (size_t i = 0; i < hash_repr_words_per_hash; ++i) {
        char sep = ((i % 4) == 3) ? '\n' : ' ';
        out << bytes_to_hex(&words[i], sizeof(words[i])) << sep;
    }
}

bool mpc_hash_read(mpc_hash_t out_hash, std::istream &in)
{
    hash_repr_word *out_data = (hash_repr_word *)out_hash;

    std::string word;
    for (size_t i = 0; i < hash_repr_words_per_hash; ++i) {
        if (!(in >> word)) {
            std::cerr << "Read failed" << std::endl;
            return false;
        }

        const std::string bin = hex_to_bytes(word);
        if (bin.size() != hash_repr_word_size) {
            std::cerr << "Invalid word size" << std::endl;
            return false;
        }

        std::memcpy(&out_data[i], bin.data(), hash_repr_word_size);
    }

    return true;
}

mpc_hash::mpc_hash() { mpc_hash_init(state); }

void mpc_hash::update(const void *data, size_t size)
{
    mpc_hash_update(state, data, size);
}

void mpc_hash::final(mpc_hash_t out_buffer)
{
    mpc_hash_final(state, out_buffer);
}

} // namespace libzeth
