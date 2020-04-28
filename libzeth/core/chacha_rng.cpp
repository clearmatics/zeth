// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/core/chacha_rng.hpp"

#include <algorithm>
#include <cstring>
#include <sodium/crypto_stream_chacha20.h>

/// RNG based on:
///   https://docs.rs/rand/0.4.6/src/rand/prng/chacha.rs.html

namespace libzeth
{

chacha_rng::chacha_rng(const void *seed, size_t seed_size)
    : data_used(sizeof(block))
{
    // Copies behaviour of ChaChaRng::from_seed() from the referenced code.
    // Use the first 8 words of seed(padding with 0 if necesary), as the key.
    seed_size = std::min(seed_size, sizeof(key));
    memcpy(key, seed, seed_size);
    if (seed_size < sizeof(key)) {
        memset(((uint8_t *)key) + seed_size, 0, sizeof(key) - seed_size);
    }

    // Reset the counter to 0.
    memset(counter, 0, sizeof(counter));
}

void chacha_rng::random(void *output, size_t output_size)
{
    // Iteratively take any remaining data in the current block, populating the
    // block with new data as required, until the output buffer is full.

    // Destination as a uint8_t pointer for easy incrementing.
    uint8_t *target = (uint8_t *)output;
    while (output_size > 0) {
        if (data_used == sizeof(block)) {
            update();
        }

        const size_t data_remaining = sizeof(block) - data_used;
        const size_t to_write = std::min(data_remaining, output_size);

        memcpy(target, &block[data_used], to_write);
        data_used += to_write;
        target += to_write;
        output_size -= to_write;
    }
}

void chacha_rng::update()
{
    // Generate a new block of random data, following the ChaChaRng::update()
    // function.

    // The referenced code uses word layout:
    //   constant constant constant constant
    //   key      key      key      key
    //   key      key      key      key
    //   counter  counter  counter  counter
    //
    // crypto_stream_chacha20_ietf_xor_ic labels these:
    //   constant constant constant constant
    //   key      key      key      key
    //   key      key      key      key
    //   ic       n        n        n
    //
    // hence counter is broken up in the call below.
    memset(block, 0, sizeof(block));
    crypto_stream_chacha20_ietf_xor_ic(
        (uint8_t *)block,
        (uint8_t *)block,
        sizeof(block),
        (const uint8_t *)&counter[1], // n
        counter[0],                   // ic
        (const uint8_t *)&key[0]);

    data_used = 0;

    // Update the counter words (treating counter as a 128-bit number), in the
    // same way as ChaChaRng::update().
    if (++counter[0] != 0) {
        return;
    }
    if (++counter[1] != 0) {
        return;
    }
    if (++counter[2] != 0) {
        return;
    }
    ++counter[3];
}

} // namespace libzeth
