// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SNARKS_PGHR13_PGHR13_SNARK_TCC__
#define __ZETH_SNARKS_PGHR13_PGHR13_SNARK_TCC__

#include "libzeth/core/field_element_utils.hpp"
#include "libzeth/core/group_element_utils.hpp"
#include "libzeth/snarks/pghr13/pghr13_snark.hpp"

namespace libzeth
{

template<typename ppT> const std::string pghr13_snark<ppT>::name("PGHR13");

template<typename ppT>
typename pghr13_snark<ppT>::keypair pghr13_snark<ppT>::generate_setup(
    const libsnark::protoboard<libff::Fr<ppT>> &pb)
{
    return libsnark::r1cs_ppzksnark_generator<ppT>(pb.get_constraint_system());
}

template<typename ppT>
typename pghr13_snark<ppT>::proof pghr13_snark<ppT>::generate_proof(
    const libsnark::protoboard<libff::Fr<ppT>> &pb,
    const pghr13_snark<ppT>::proving_key &proving_key)
{
    return generate_proof(
        proving_key, pb.primary_input(), pb.auxiliary_input());
}

template<typename ppT>
typename pghr13_snark<ppT>::proof pghr13_snark<ppT>::generate_proof(
    const pghr13_snark<ppT>::proving_key &proving_key,
    const libsnark::r1cs_primary_input<libff::Fr<ppT>> &primary_input,
    const libsnark::r1cs_auxiliary_input<libff::Fr<ppT>> auxiliary_input)
{
    // Generate proof from public input, auxiliary input (private/secret data),
    // and proving key
    return libsnark::r1cs_ppzksnark_prover(
        proving_key, primary_input, auxiliary_input);
}

template<typename ppT>
bool pghr13_snark<ppT>::verify(
    const libsnark::r1cs_primary_input<libff::Fr<ppT>> &primary_inputs,
    const pghr13_snark<ppT>::proof &proof,
    const pghr13_snark<ppT>::verification_key &verification_key)
{
    return libsnark::r1cs_ppzksnark_verifier_strong_IC<ppT>(
        verification_key, primary_inputs, proof);
}

template<typename ppT>
void pghr13_snark<ppT>::verification_key_write_json(
    const pghr13_snark<ppT>::verification_key &vk, std::ostream &os)
{
    unsigned ic_length = vk.encoded_IC_query.rest.indices.size() + 1;

    os << "{\n";
    os << " \"a\": " << group_element_to_json(vk.alphaA_g2) << ",\n";
    os << " \"b\": " << group_element_to_json(vk.alphaB_g1) << ",\n";
    os << " \"c\": " << group_element_to_json(vk.alphaC_g2) << ",\n";
    os << " \"g\": " << group_element_to_json(vk.gamma_g2) << ",\n";
    os << " \"gb1\": " << group_element_to_json(vk.gamma_beta_g1) << ",\n";
    os << " \"gb2\": " << group_element_to_json(vk.gamma_beta_g2) << ",\n";
    os << " \"z\": " << group_element_to_json(vk.rC_Z_g2) << ",\n";

    os << "\"IC\" :[" << group_element_to_json(vk.encoded_IC_query.first);

    for (size_t i = 1; i < ic_length; ++i) {
        os << ","
           << group_element_to_json(vk.encoded_IC_query.rest.values[i - 1]);
    }

    os << "]\n";
    os << "}";
}

template<typename ppT>
void pghr13_snark<ppT>::verification_key_write_bytes(
    const typename pghr13_snark<ppT>::verification_key &vk, std::ostream &os)
{
    os << vk;
}

template<typename ppT>
void pghr13_snark<ppT>::verification_key_read_bytes(
    typename pghr13_snark<ppT>::verification_key &vk, std::istream &in_s)
{
    in_s >> vk;
}

template<typename ppT>
void pghr13_snark<ppT>::proving_key_write_bytes(
    const typename pghr13_snark<ppT>::proving_key &pk, std::ostream &os)
{
    os << pk;
}

template<typename ppT>
void pghr13_snark<ppT>::proving_key_read_bytes(
    typename pghr13_snark<ppT>::proving_key &pk, std::istream &in_s)
{
    in_s >> pk;
}

template<typename ppT>
void pghr13_snark<ppT>::proof_write_json(
    const typename pghr13_snark<ppT>::proof &proof, std::ostream &os)
{
    os << "{\n";
    os << " \"a\": " << group_element_to_json(proof.g_A.g) << ",\n";
    os << " \"a_p\": " << group_element_to_json(proof.g_A.h) << ",\n";
    os << " \"b\": " << group_element_to_json(proof.g_B.g) << ",\n";
    os << " \"b_p\": " << group_element_to_json(proof.g_B.h) << ",\n";
    os << " \"c\": " << group_element_to_json(proof.g_C.g) << ",\n";
    os << " \"c_p\": " << group_element_to_json(proof.g_C.h) << ",\n";
    os << " \"h\": " << group_element_to_json(proof.g_H) << ",\n";
    os << " \"k\": " << group_element_to_json(proof.g_K) << "\n";
    os << "}";
}

template<typename ppT>
void pghr13_snark<ppT>::proof_write_bytes(
    const typename pghr13_snark<ppT>::proof &proof, std::ostream &out_s)
{
    knowledge_commitment_write_bytes(proof.g_A, out_s);
    knowledge_commitment_write_bytes(proof.g_B, out_s);
    knowledge_commitment_write_bytes(proof.g_C, out_s);
    group_element_write_bytes(proof.g_H, out_s);
    group_element_write_bytes(proof.g_K, out_s);
}

template<typename ppT>
void pghr13_snark<ppT>::proof_read_bytes(
    typename pghr13_snark<ppT>::proof &proof, std::istream &in_s)
{
    knowledge_commitment_read_bytes(proof.g_A, in_s);
    knowledge_commitment_read_bytes(proof.g_B, in_s);
    knowledge_commitment_read_bytes(proof.g_C, in_s);
    group_element_read_bytes(proof.g_H, in_s);
    group_element_read_bytes(proof.g_K, in_s);
}

template<typename ppT>
void pghr13_snark<ppT>::keypair_write_bytes(
    const typename pghr13_snark<ppT>::keypair &keypair, std::ostream &os)
{
    proving_key_write_bytes(keypair.pk, os);
    verification_key_write_bytes(keypair.vk, os);
}

template<typename ppT>
void pghr13_snark<ppT>::keypair_read_bytes(
    typename pghr13_snark<ppT>::keypair &keypair, std::istream &in_s)
{
    proving_key_read_bytes(keypair.pk, in_s);
    verification_key_read_bytes(keypair.vk, in_s);
}

} // namespace libzeth

#endif // __ZETH_SNARKS_PGHR13_PGHR13_SNARK_TCC__
