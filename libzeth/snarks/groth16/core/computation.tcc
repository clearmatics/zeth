// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SNARKS_CORE_COMPUTATION_TCC__
#define __ZETH_SNARKS_CORE_COMPUTATION_TCC__

#include "libzeth/snarks/groth16/core/computation.hpp"

namespace libzeth
{

// Generate the proof and returns a struct {proof, primary_input}
template<typename ppT>
libsnark::r1cs_gg_ppzksnark_proof<ppT> generate_proof(
    const libsnark::protoboard<libff::Fr<ppT>> &pb,
    const libsnark::r1cs_gg_ppzksnark_proving_key<ppT> &proving_key)
{
    libsnark::r1cs_primary_input<libff::Fr<ppT>> primary_input =
        pb.primary_input();
    libsnark::r1cs_auxiliary_input<libff::Fr<ppT>> auxiliary_input =
        pb.auxiliary_input();

    // Generate proof from public input, auxiliary input and proving key.
    // For now, force a pow2 domain, in case the key came from the MPC.
    libsnark::r1cs_gg_ppzksnark_proof<ppT> proof = libsnark::r1cs_gg_ppzksnark_prover(
        proving_key, primary_input, auxiliary_input, true);

    return proof;
};

// Run the trusted setup and returns a struct {proving_key, verifying_key}
template<typename ppT>
libsnark::r1cs_gg_ppzksnark_keypair<ppT> generate_setup(
    const libsnark::protoboard<libff::Fr<ppT>> &pb)
{
    // Generate verification and proving key from the R1CS
    return libsnark::r1cs_gg_ppzksnark_generator<ppT>(
        pb.get_constraint_system(), true);
};

// Verification of a proof
template<typename ppT>
bool verify(
    const libzeth::extended_proof<ppT> &ext_proof,
    const libsnark::r1cs_gg_ppzksnark_verification_key<ppT> &verification_key)
{
    return libsnark::r1cs_gg_ppzksnark_verifier_strong_IC<ppT>(
        verification_key, ext_proof.get_primary_input(), ext_proof.get_proof());
};

} // namespace libzeth

#endif // __ZETH_SNARKS_CORE_COMPUTATION_TCC__
