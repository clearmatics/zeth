// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SNARKS_GROTH16_GROTH16_SNARK_TCC__
#define __ZETH_SNARKS_GROTH16_GROTH16_SNARK_TCC__

#include "libzeth/core/group_element_utils.hpp"
#include "libzeth/core/utils.hpp"
#include "libzeth/snarks/groth16/groth16_snark.hpp"

namespace libzeth
{

template<typename ppT>
typename groth16_snark<ppT>::keypair groth16_snark<ppT>::generate_setup(
    const libsnark::protoboard<libff::Fr<ppT>> &pb)
{
    // Generate verification and proving key from the R1CS
    return libsnark::r1cs_gg_ppzksnark_generator<ppT>(
        pb.get_constraint_system(), true);
}

template<typename ppT>
typename groth16_snark<ppT>::proof groth16_snark<ppT>::generate_proof(
    const libsnark::protoboard<libff::Fr<ppT>> &pb,
    const typename groth16_snark<ppT>::proving_key &proving_key)
{
    libsnark::r1cs_primary_input<libff::Fr<ppT>> primary_input =
        pb.primary_input();
    libsnark::r1cs_auxiliary_input<libff::Fr<ppT>> auxiliary_input =
        pb.auxiliary_input();

    // Generate proof from public input, auxiliary input and proving key.
    // For now, force a pow2 domain, in case the key came from the MPC.
    return libsnark::r1cs_gg_ppzksnark_prover(
        proving_key, primary_input, auxiliary_input, true);
}

template<typename ppT>
bool groth16_snark<ppT>::verify(
    const libsnark::r1cs_primary_input<libff::Fr<ppT>> &primary_inputs,
    const groth16_snark<ppT>::proof &proof,
    const groth16_snark<ppT>::verification_key &verification_key)
{
    return libsnark::r1cs_gg_ppzksnark_verifier_strong_IC<ppT>(
        verification_key, primary_inputs, proof);
}

template<typename ppT>
std::ostream &groth16_snark<ppT>::verification_key_write_json(
    const verification_key &vk, std::ostream &os)
{
    const size_t abc_length = vk.ABC_g1.rest.indices.size() + 1;
    os << "{"
       << "\n"
       << "  \"alpha\": " << point_affine_to_json(vk.alpha_g1) << ",\n"
       << "  \"beta\": " << point_affine_to_json(vk.beta_g2) << ",\n"
       << "  \"delta\": " << point_affine_to_json(vk.delta_g2) << ",\n"
       << "  \"ABC\": [\n    " << point_affine_to_json(vk.ABC_g1.first);
    for (size_t i = 1; i < abc_length; ++i) {
        os << ",\n    " << point_affine_to_json(vk.ABC_g1.rest.values[i - 1]);
    }
    return os << "\n  ]\n}";
}

template<typename ppT>
std::ostream &groth16_snark<ppT>::verification_key_write_bytes(
    const verification_key &vk, std::ostream &os)
{
    if (!is_well_formed<ppT>(vk)) {
        throw std::invalid_argument("verification key (write) not well-formed");
    }
    return os << vk;
}

template<typename ppT>
std::ostream &groth16_snark<ppT>::proving_key_write_bytes(
    const proving_key &pk, std::ostream &os)
{
    if (!is_well_formed<ppT>(pk)) {
        throw std::invalid_argument("proving key (write) not well-formed");
    }
    return os << pk;
}

template<typename ppT>
typename groth16_snark<ppT>::verification_key groth16_snark<
    ppT>::verification_key_read_bytes(std::istream &is)
{
    verification_key vk;
    is >> vk;
    if (!is_well_formed<ppT>(vk)) {
        throw std::invalid_argument("verification key (read) not well-formed");
    }
    return vk;
}

template<typename ppT>
typename groth16_snark<ppT>::proving_key groth16_snark<
    ppT>::proving_key_read_bytes(std::istream &is)
{
    proving_key pk;
    is >> pk;
    if (!is_well_formed<ppT>(pk)) {
        throw std::invalid_argument("proving key (read) not well-formed");
    }
    return pk;
}

template<typename ppT>
std::ostream &groth16_snark<ppT>::keypair_write_bytes(
    std::ostream &os, const typename groth16_snark<ppT>::keypair &keypair)
{
    proving_key_write_bytes(keypair.pk, os);
    verification_key_write_bytes(keypair.vk, os);
    return os;
}

template<typename ppT>
typename groth16_snark<ppT>::keypair groth16_snark<ppT>::keypair_read_bytes(
    std::istream &is)
{
    proving_key pk = proving_key_read_bytes(is);
    verification_key vk = verification_key_read_bytes(is);
    return libsnark::r1cs_gg_ppzksnark_keypair<ppT>(
        std::move(pk), std::move(vk));
}

template<typename ppT>
std::ostream &groth16_snark<ppT>::proof_write_json(
    const typename groth16_snark<ppT>::proof &proof, std::ostream &os)
{
    os << "{\n  \"a\": " << point_affine_to_json(proof.g_A)
       << ",\n  \"b\": " << point_affine_to_json(proof.g_B)
       << ",\n  \"c\": " << point_affine_to_json(proof.g_C) << "\n}";
    return os;
}

template<typename ppT>
bool is_well_formed(const typename groth16_snark<ppT>::proving_key &pk)
{
    if (!pk.alpha_g1.is_well_formed() || !pk.beta_g1.is_well_formed() ||
        !pk.beta_g2.is_well_formed() || !pk.delta_g1.is_well_formed() ||
        !pk.delta_g2.is_well_formed() ||
        !container_is_well_formed(pk.A_query) ||
        !container_is_well_formed(pk.L_query)) {
        return false;
    }

    using knowledge_commitment =
        libsnark::knowledge_commitment<libff::G2<ppT>, libff::G1<ppT>>;
    for (const knowledge_commitment &b : pk.B_query.values) {
        if (!b.g.is_well_formed() || !b.h.is_well_formed()) {
            return false;
        }
    }

    return true;
}

template<typename ppT>
bool is_well_formed(const typename groth16_snark<ppT>::verification_key &vk)
{
    if (!vk.alpha_g1.is_well_formed() || !vk.beta_g2.is_well_formed() ||
        !vk.delta_g2.is_well_formed() || !vk.ABC_g1.first.is_well_formed()) {
        return false;
    }

    return container_is_well_formed(vk.ABC_g1.rest.values);
}

} // namespace libzeth

#endif // __ZETH_SNARKS_GROTH16_GROTH16_SNARK_TCC__
