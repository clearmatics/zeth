// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SNARKS_GROTH16_GROTH16_SNARK_HPP__
#define __ZETH_SNARKS_GROTH16_GROTH16_SNARK_HPP__

#include <boost/filesystem.hpp>
#include <libsnark/gadgetlib1/protoboard.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

namespace libzeth
{

/// Core types and operations for the GROTH16 snark
template<typename ppT> class groth16_snark
{
public:
    typedef libsnark::r1cs_gg_ppzksnark_proving_key<ppT> ProvingKeyT;
    typedef libsnark::r1cs_gg_ppzksnark_verification_key<ppT> VerifKeyT;
    typedef libsnark::r1cs_gg_ppzksnark_keypair<ppT> KeypairT;
    typedef libsnark::r1cs_gg_ppzksnark_proof<ppT> ProofT;

    // Run the trusted setup and return the keypair for the circuit
    static KeypairT generate_setup(
        const libsnark::protoboard<libff::Fr<ppT>> &pb);

    // Generate the proof
    static ProofT generate_proof(
        const libsnark::protoboard<libff::Fr<ppT>> &pb,
        const ProvingKeyT &proving_key);

    // Verification of a proof
    static bool verify(
        const libsnark::r1cs_primary_input<libff::Fr<ppT>> &primary_inputs,
        const ProofT &proof,
        const VerifKeyT &verification_key);

    // TODO: These should be refactored to be generic calls in terms of simple
    // snark-specific methods.

    static void export_verification_key(const KeypairT &keypair);

    static void display_proof(const ProofT &proof);

    static void verification_key_to_json(
        const VerifKeyT &vk, boost::filesystem::path path = "");

    static void proof_and_inputs_to_json(
        const ProofT &proof,
        const libsnark::r1cs_primary_input<libff::Fr<ppT>> &input,
        boost::filesystem::path path = "");

    static void proof_to_json(
        const ProofT &proof, boost::filesystem::path path);

    /// Write a keypair to a stream.
    static void write_keypair(std::ostream &out, const KeypairT &keypair);

    /// Read a keypair from a stream.
    static KeypairT read_keypair(std::istream &in);
};

/// Check well-formedness of a proving key
template<typename ppT>
static bool is_well_formed(const typename groth16_snark<ppT>::ProvingKeyT &pk);

/// Check well-formedness of a verification key
template<typename ppT>
static bool is_well_formed(const typename groth16_snark<ppT>::VerifKeyT &vk);

} // namespace libzeth

#include "libzeth/snarks/groth16/groth16_snark.tcc"

#endif // __ZETH_SNARKS_GROTH16_GROTH16_SNARK_HPP__
