#include "snarks/groth16/mpc/chacha_rng.hpp"

#include <algorithm>
#include <cstring>

// Reference implementation of chacha20 in libsodium
extern "C" int stream_ietf_ext_ref_xor_ic(
    uint8_t *c,
    const uint8_t *m,
    size_t mlen,
    const uint8_t *n,
    uint32_t ic,
    const uint8_t *k);

namespace libzeth
{

chacha_rng::chacha_rng(const void *seed, size_t seed_size)
    : data_used(sizeof(data))
{
    seed_size = std::min(seed_size, sizeof(key));
    memcpy(key, seed, seed_size);
    if (seed_size < sizeof(key)) {
        memset(((uint8_t *)key) + seed_size, 0, sizeof(key) - seed_size);
    }
    memset(iv, 0, sizeof(iv));
}

void chacha_rng::random(void *const output, size_t output_size)
{
    memset(output, 0, output_size);

    uint8_t *target = (uint8_t *)output;
    while (output_size > 0) {
        if (data_used == sizeof(data)) {
            populate();
        }

        const size_t data_remaining = sizeof(data) - data_used;
        const size_t to_write = std::min(data_remaining, output_size);

        memcpy(target, &data[data_used], to_write);
        data_used += to_write;
        target += to_write;
        output_size -= to_write;
    }
}

void chacha_rng::populate()
{
    memset(data, 0, sizeof(data));
    stream_ietf_ext_ref_xor_ic(
        // crypto_stream_chacha20_ietf_xor_ic(
        (uint8_t *)data,
        (uint8_t *)data,
        sizeof(data),
        (const uint8_t *)&iv[1],
        iv[0],
        (const uint8_t *)&key[0]);

    data_used = 0;
    if (++iv[0] != 0) {
        return;
    }
    if (++iv[1] != 0) {
        return;
    }
    if (++iv[2] != 0) {
        return;
    }
    ++iv[3];
}

} // namespace libzeth
