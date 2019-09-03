#ifndef __ZETH_SNARKS_GROTH16_MPC_PHASE2_HPP__
#define __ZETH_SNARKS_GROTH16_MPC_PHASE2_HPP__

#include "include_libsnark.hpp"

#include <sodium/crypto_generichash_blake2b.h>

namespace libzeth
{

template<typename ppT> class srs_powersoftau;
template<typename ppT> class srs_mpc_layer_L1;

// Hashing for MPC.  Streaming and whole-buffer interfaces.
const size_t srs_mpc_hash_size = 64;
const size_t srs_mpc_hash_array_length = srs_mpc_hash_size / sizeof(size_t);
using srs_mpc_hash_t = size_t[srs_mpc_hash_array_length];

using srs_mpc_hash_state_t = crypto_generichash_blake2b_state;
void srs_mpc_hash_init(srs_mpc_hash_state_t &);
void srs_mpc_hash_update(srs_mpc_hash_state_t &, const void *, size_t);
void srs_mpc_hash_final(srs_mpc_hash_state_t &, srs_mpc_hash_t);
void srs_mpc_compute_hash(
    srs_mpc_hash_t out_hash, const void *data, size_t data_size);

/// Data that is updated py participants in the MPC for Phase2 of the SRS
/// generation.
template<typename ppT> class srs_mpc_phase2_accumulator
{
public:
    libff::G1<ppT> delta_g1;
    libff::G2<ppT> delta_g2;
    libff::G1_vector<ppT> H_g1;
    libff::G1_vector<ppT> L_g1;

    srs_mpc_phase2_accumulator(
        const libff::G1<ppT> &delta_g1,
        const libff::G2<ppT> &delta_g2,
        libff::G1_vector<ppT> &&H_g1,
        libff::G1_vector<ppT> &&L_g1);

    bool is_well_formed() const;
    void write(std::ostream &out) const;
    static srs_mpc_phase2_accumulator<ppT> read(std::istream &in);
};

/// Final output from the second phase of the MPC.  A sub-set of the
/// L1 data divided by a secret $\delta$.
template<typename ppT> using srs_mpc_layer_C2 = srs_mpc_phase2_accumulator<ppT>;

/// Given the output from the first layer of the MPC, perform the 2nd
/// layer computation using just local randomness for delta. This is not a
/// substitute for the full MPC with an auditable log of
/// contributions, but is useful for testing.
template<typename ppT>
srs_mpc_layer_C2<ppT> mpc_dummy_layer_C2(
    const srs_mpc_layer_L1<ppT> &layer1,
    const libff::Fr<ppT> &delta,
    size_t num_inputs);

/// Given the output from all phases of the MPC, create the
/// prover and verification keys for the given circuit.
template<typename ppT>
libsnark::r1cs_gg_ppzksnark_keypair<ppT> mpc_create_key_pair(
    srs_powersoftau<ppT> &&pot,
    srs_mpc_layer_L1<ppT> &&layer1,
    srs_mpc_layer_C2<ppT> &&layer2,
    libsnark::r1cs_constraint_system<libff::Fr<ppT>> &&cs,
    const libsnark::qap_instance<libff::Fr<ppT>> &qap);

/// Check proving key entries
template<typename ppT>
bool is_well_formed(const libsnark::r1cs_gg_ppzksnark_proving_key<ppT> &pk);

/// Check verification key entries
template<typename ppT>
bool is_well_formed(
    const libsnark::r1cs_gg_ppzksnark_verification_key<ppT> &vk);

/// Write a keypair to a stream.
template<typename ppT>
void mpc_write_keypair(
    std::ostream &out, const libsnark::r1cs_gg_ppzksnark_keypair<ppT> keypair);

/// Read a keypair from a stream.
template<typename ppT>
libsnark::r1cs_gg_ppzksnark_keypair<ppT> mpc_read_keypair(std::istream &in);

} // namespace libzeth

#include "snarks/groth16/mpc_phase2.tcc"

#endif // __ZETH_SNARKS_GROTH16_MPC_PHASE2_HPP__
