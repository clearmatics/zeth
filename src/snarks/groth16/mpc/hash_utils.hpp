#ifndef __ZETH_SNARKS_GROTH16_MPC_HASH_UTILS_HPP__
#define __ZETH_SNARKS_GROTH16_MPC_HASH_UTILS_HPP__

#include <ios>
#include <iostream>
#include <sodium/crypto_generichash_blake2b.h>

namespace libzeth
{

// Hashing for MPC. Streaming and whole-buffer interfaces.
const size_t srs_mpc_hash_size = 64;
const size_t srs_mpc_hash_array_length = srs_mpc_hash_size / sizeof(size_t);
using srs_mpc_hash_t = size_t[srs_mpc_hash_array_length];

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

/// Parse a human-readable string (4 x 4 x 4-byte hex words) reprsenting an
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

class hash_ostream : public std::ostream
{
public:
    hash_ostream();
    void get_hash(srs_mpc_hash_t out_hash);

private:
    hash_streambuf hsb;
};

} // namespace libzeth

#endif // __ZETH_SNARKS_GROTH16_MPC_HASH_UTILS_HPP__
