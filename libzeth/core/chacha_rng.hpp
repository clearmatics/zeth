// Copyright (c) 2015-2022 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CORE_CHACHA_RNG_HPP__
#define __ZETH_CORE_CHACHA_RNG_HPP__

#include <cstddef>
#include <cstdint>

namespace libzeth
{

/// Random number generator matching the implementation used by zcash
/// powersoftau and phase2.
/// Usage:
///   https://github.com/clearmatics/powersoftau
///   (See hash_to_g2 function)
/// Implementation is based on:
///   https://docs.rs/rand/0.4.6/src/rand/prng/chacha.rs.html
///   (See description comment, in particular word layout)
class chacha_rng
{
public:
    chacha_rng(const void *seed, size_t seed_size);
    void random(void *output, size_t output_size);

private:
    void update();

    // The key generated from the seed data
    uint32_t key[8];

    // 128-bit counter
    uint32_t counter[4];

    // Current block of output from chacha
    uint8_t block[64];

    // Number of bytes of data already used from block
    size_t data_used;
};

} // namespace libzeth

#endif // __ZETH_CORE_CHACHA_RNG_HPP__
