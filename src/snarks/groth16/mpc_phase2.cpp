#include "snarks/groth16/mpc_phase2.hpp"

namespace libzeth
{

static_assert(srs_mpc_hash_size % sizeof(size_t) == 0, "invalid hash size");
static_assert(
    srs_mpc_hash_size == crypto_generichash_blake2b_BYTES_MAX,
    "unexpected hash size");

void srs_mpc_hash_init(srs_mpc_hash_state_t &state)
{
    crypto_generichash_blake2b_init(&state, nullptr, 0, srs_mpc_hash_size);
}

void srs_mpc_hash_update(
    srs_mpc_hash_state_t &state, const void *in, size_t size)
{
    crypto_generichash_blake2b_update(&state, (const uint8_t *)in, size);
}

void srs_mpc_hash_final(srs_mpc_hash_state_t &state, srs_mpc_hash_t out_hash)
{
    crypto_generichash_blake2b_final(
        &state, (uint8_t *)out_hash, srs_mpc_hash_size);
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

hash_streambuf::hash_streambuf() { srs_mpc_hash_init(hash_state); }

std::streamsize hash_streambuf::xsputn(const char *s, std::streamsize n)
{
    srs_mpc_hash_update(hash_state, s, n);
    return n;
}

hash_ostream::hash_ostream() : std::ostream(&hsb), hsb() {}

void hash_ostream::get_hash(srs_mpc_hash_t out_hash)
{
    srs_mpc_hash_final(hsb.hash_state, out_hash);
}

} // namespace libzeth
