// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SNARKS_PGHR13_PGHR13_SNARK_TCC__
#define __ZETH_SNARKS_PGHR13_PGHR13_SNARK_TCC__

#include "libzeth/core/field_element_utils.hpp"
#include "libzeth/core/group_element_utils.hpp"
#include "libzeth/snarks/pghr13/pghr13_snark.hpp"

namespace libzeth
{

template<typename ppT>
typename pghr13_snark<ppT>::KeypairT pghr13_snark<ppT>::generate_setup(
    const libsnark::protoboard<libff::Fr<ppT>> &pb)
{
    return libsnark::r1cs_ppzksnark_generator<ppT>(pb.get_constraint_system());
}

template<typename ppT>
typename pghr13_snark<ppT>::ProofT pghr13_snark<ppT>::generate_proof(
    const libsnark::protoboard<libff::Fr<ppT>> &pb,
    const pghr13_snark<ppT>::ProvingKeyT &proving_key)
{
    // See:
    // https://github.com/scipr-lab/libsnark/blob/92a80f74727091fdc40e6021dc42e9f6b67d5176/libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp#L81
    // For the definition of r1cs_primary_input and r1cs_auxiliary_input
    libsnark::r1cs_primary_input<libff::Fr<ppT>> primary_input =
        pb.primary_input();
    libsnark::r1cs_auxiliary_input<libff::Fr<ppT>> auxiliary_input =
        pb.auxiliary_input();

    // Generate proof from public input, auxiliary input (private/secret data),
    // and proving key
    ProofT proof = libsnark::r1cs_ppzksnark_prover(
        proving_key, primary_input, auxiliary_input);

    return proof;
}

template<typename ppT>
bool pghr13_snark<ppT>::verify(
    const libsnark::r1cs_primary_input<libff::Fr<ppT>> &primary_inputs,
    const pghr13_snark<ppT>::ProofT &proof,
    const pghr13_snark<ppT>::VerificationKeyT &verification_key)
{
    return libsnark::r1cs_ppzksnark_verifier_strong_IC<ppT>(
        verification_key, primary_inputs, proof);
}

template<typename ppT>
std::ostream &pghr13_snark<ppT>::verification_key_write_json(
    const pghr13_snark<ppT>::VerificationKeyT &vk, std::ostream &os)
{
    unsigned ic_length = vk.encoded_IC_query.rest.indices.size() + 1;

    os << "{\n";
    os << " \"a\": " << point_g2_affine_to_json<ppT>(vk.alphaA_g2) << ",\n";
    os << " \"b\": " << point_g1_affine_to_json<ppT>(vk.alphaB_g1) << ",\n";
    os << " \"c\": " << point_g2_affine_to_json<ppT>(vk.alphaC_g2) << ",\n";
    os << " \"g\": " << point_g2_affine_to_json<ppT>(vk.gamma_g2) << ",\n";
    os << " \"gb1\": " << point_g1_affine_to_json<ppT>(vk.gamma_beta_g1)
       << ",\n";
    os << " \"gb2\": " << point_g2_affine_to_json<ppT>(vk.gamma_beta_g2)
       << ",\n";
    os << " \"z\": " << point_g2_affine_to_json<ppT>(vk.rC_Z_g2) << ",\n";

    os << "\"IC\" :["
       << point_g1_affine_to_json<ppT>(vk.encoded_IC_query.first);

    for (size_t i = 1; i < ic_length; ++i) {
        os << ","
           << point_g1_affine_to_json<ppT>(
                  vk.encoded_IC_query.rest.values[i - 1]);
    }

    os << "]\n";
    os << "}";
    return os;
}

template<typename ppT>
std::ostream &pghr13_snark<ppT>::verification_key_write_bytes(
    const typename pghr13_snark<ppT>::VerificationKeyT &vk, std::ostream &os)
{
    return os << vk;
}

template<typename ppT>
typename pghr13_snark<ppT>::VerificationKeyT pghr13_snark<
    ppT>::verification_key_read_bytes(std::istream &is)
{
    VerificationKeyT vk;
    is >> vk;
    return vk;
}

template<typename ppT>
std::ostream &pghr13_snark<ppT>::proving_key_write_bytes(
    const typename pghr13_snark<ppT>::ProvingKeyT &pk, std::ostream &os)
{
    return os << pk;
}

template<typename ppT>
typename pghr13_snark<ppT>::ProvingKeyT pghr13_snark<
    ppT>::proving_key_read_bytes(std::istream &is)
{
    ProvingKeyT pk;
    is >> pk;
    return pk;
}

template<typename ppT>
std::ostream &pghr13_snark<ppT>::proof_write_json(
    const typename pghr13_snark<ppT>::ProofT &proof, std::ostream &os)
{
    return os << proof;
}

template<typename ppT>
std::ostream &pghr13_snark<ppT>::keypair_write_bytes(
    const typename pghr13_snark<ppT>::KeypairT &keypair, std::ostream &os)
{
    proving_key_write_bytes(keypair.pk, os);
    return verification_key_write_bytes(keypair.vk, os);
}

template<typename ppT>
typename pghr13_snark<ppT>::KeypairT pghr13_snark<ppT>::keypair_read_bytes(
    std::istream &is)
{
    return KeypairT(
        proving_key_read_bytes(is), verification_key_read_bytes(is));
}

} // namespace libzeth

#endif // __ZETH_SNARKS_PGHR13_PGHR13_SNARK_TCC__
