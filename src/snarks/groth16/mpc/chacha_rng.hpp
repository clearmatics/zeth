#ifndef __ZETH__SNARKS_GROTH16_MPC_CHACHA_RNG_HPP__
#define __ZETH__SNARKS_GROTH16_MPC_CHACHA_RNG_HPP__

#include <cstddef>
#include <cstdint>

namespace libzeth
{

// Random number generator matching the implementation used by zcash
// powersoftau and phase2.
class chacha_rng
{
public:
    chacha_rng(const void *seed, size_t seed_size);
    void random(void *output, size_t output_size);

private:
    void populate();

    uint32_t key[8];
    uint32_t iv[4];
    uint8_t data[64];
    size_t data_used;
};

} // namespace libzeth

#endif // __ZETH__SNARKS_GROTH16_MPC_CHACHA_RNG_HPP__
