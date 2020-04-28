// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/snarks/groth16/mpc/hash_utils.hpp"

#include "libzeth/core/utils.hpp"

namespace libzeth
{

// In the text representation, use 16 x 4-byte words, (each representated as 8
// digits + separator).
using hash_repr_word = uint32_t;
const size_t HASH_REPR_WORD_SIZE = sizeof(hash_repr_word);
const size_t HASH_REPR_WORDS_PER_HASH = SRS_MPC_HASH_SIZE / HASH_REPR_WORD_SIZE;

static_assert(SRS_MPC_HASH_SIZE % sizeof(size_t) == 0, "invalid hash size");
static_assert(
    SRS_MPC_HASH_SIZE == crypto_generichash_blake2b_BYTES_MAX,
    "unexpected hash size");

void srs_mpc_hash_init(srs_mpc_hash_state_t &state)
{
    crypto_generichash_blake2b_init(&state, nullptr, 0, SRS_MPC_HASH_SIZE);
}

void srs_mpc_hash_update(
    srs_mpc_hash_state_t &state, const void *in, size_t size)
{
    crypto_generichash_blake2b_update(&state, (const uint8_t *)in, size);
}

void srs_mpc_hash_final(srs_mpc_hash_state_t &state, srs_mpc_hash_t out_hash)
{
    crypto_generichash_blake2b_final(
        &state, (uint8_t *)out_hash, SRS_MPC_HASH_SIZE);
}

void srs_mpc_compute_hash(
    srs_mpc_hash_t out_hash, const void *data, size_t data_size)
{
    srs_mpc_hash_state_t s;
    srs_mpc_hash_init(s);
    srs_mpc_hash_update(s, data, data_size);
    srs_mpc_hash_final(s, out_hash);
}

void srs_mpc_compute_hash(srs_mpc_hash_t out_hash, const std::string &data)
{
    srs_mpc_compute_hash(out_hash, data.data(), data.size());
}

void srs_mpc_hash_write(const srs_mpc_hash_t hash, std::ostream &out)
{
    const hash_repr_word *words = (const hash_repr_word *)hash;

    for (size_t i = 0; i < HASH_REPR_WORDS_PER_HASH; ++i) {
        char sep = ((i % 4) == 3) ? '\n' : ' ';
        out << binary_str_to_hexadecimal_str(&words[i], sizeof(words[i]))
            << sep;
    }
}

bool srs_mpc_hash_read(srs_mpc_hash_t out_hash, std::istream &in)
{
    hash_repr_word *out_data = (hash_repr_word *)out_hash;

    std::string word;
    for (size_t i = 0; i < HASH_REPR_WORDS_PER_HASH; ++i) {
        if (!(in >> word)) {
            std::cerr << "Read failed" << std::endl;
            return false;
        }

        const std::string bin = hexadecimal_str_to_binary_str(word);
        if (bin.size() != HASH_REPR_WORD_SIZE) {
            std::cerr << "Invalid word size" << std::endl;
            return false;
        }

        memcpy(&out_data[i], bin.data(), HASH_REPR_WORD_SIZE);
    }

    return true;
}

hash_streambuf::hash_streambuf() { srs_mpc_hash_init(hash_state); }

std::streamsize hash_streambuf::xsputn(const char *s, std::streamsize n)
{
    srs_mpc_hash_update(hash_state, s, n);
    return n;
}

hash_streambuf_wrapper::hash_streambuf_wrapper(std::ostream *inner)
    : inner_out(inner)
{
    srs_mpc_hash_init(hash_state);
}

hash_streambuf_wrapper::hash_streambuf_wrapper(std::istream *inner)
    : inner_in(inner)
{
    srs_mpc_hash_init(hash_state);
}

std::streamsize hash_streambuf_wrapper::xsputn(const char *s, std::streamsize n)
{
    inner_out->write(s, n);
    srs_mpc_hash_update(hash_state, s, n);
    return n;
}

std::streamsize hash_streambuf_wrapper::xsgetn(char *s, std::streamsize n)
{
    inner_in->read(s, n);
    srs_mpc_hash_update(hash_state, s, n);
    return n;
}

hash_ostream::hash_ostream() : std::ostream(&hsb), hsb() {}

void hash_ostream::get_hash(srs_mpc_hash_t out_hash)
{
    srs_mpc_hash_final(hsb.hash_state, out_hash);
}

hash_ostream_wrapper::hash_ostream_wrapper(std::ostream &inner_stream)
    : std::ostream(&hsb), hsb(&inner_stream)
{
}

void hash_ostream_wrapper::get_hash(srs_mpc_hash_t out_hash)
{
    srs_mpc_hash_final(hsb.hash_state, out_hash);
}

hash_istream_wrapper::hash_istream_wrapper(std::istream &inner_stream)
    : std::istream(&hsb), hsb(&inner_stream)
{
}

void hash_istream_wrapper::get_hash(srs_mpc_hash_t out_hash)
{
    srs_mpc_hash_final(hsb.hash_state, out_hash);
}

} // namespace libzeth
