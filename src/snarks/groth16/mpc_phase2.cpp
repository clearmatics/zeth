#include "snarks/groth16/mpc_phase2.hpp"

namespace libzeth
{

static_assert(srs_mpc_hash_size % sizeof(size_t) == 0, "invalid hash size");
static_assert(srs_mpc_hash_size == BLAKE2B_OUTBYTES, "unexpected hash size");

void srs_mpc_hash_init(srs_mpc_hash_state_t &state)
{
    blake2b_init(&state, BLAKE2B_OUTBYTES);
}

void srs_mpc_hash_update(
    srs_mpc_hash_state_t &state, const void *in, size_t size)
{
    blake2b_update(&state, in, size);
}

void srs_mpc_hash_final(srs_mpc_hash_state_t &state, srs_mpc_hash_t out_hash)
{
    blake2b_final(&state, out_hash, srs_mpc_hash_size);
}

void srs_mpc_compute_hash(
    srs_mpc_hash_t out_hash, const void *data, size_t data_size)
{
    srs_mpc_hash_state_t s;
    srs_mpc_hash_init(s);
    srs_mpc_hash_update(s, data, data_size);
    srs_mpc_hash_final(s, out_hash);
}

} // namespace libzeth