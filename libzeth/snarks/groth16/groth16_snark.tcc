// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SNARKS_GROTH16_GROTH16_SNARK_TCC__
#define __ZETH_SNARKS_GROTH16_GROTH16_SNARK_TCC__

#include "libzeth/core/group_element_utils.hpp"
#include "libzeth/core/utils.hpp"
#include "libzeth/serialization/filesystem_util.hpp" // TODO: remove this
#include "libzeth/snarks/groth16/groth16_snark.hpp"

namespace libzeth
{

template<typename ppT>
typename groth16_snark<ppT>::KeypairT groth16_snark<ppT>::generate_setup(
    const libsnark::protoboard<libff::Fr<ppT>> &pb)
{
    // Generate verification and proving key from the R1CS
    return libsnark::r1cs_gg_ppzksnark_generator<ppT>(
        pb.get_constraint_system(), true);
}

template<typename ppT>
typename groth16_snark<ppT>::ProofT groth16_snark<ppT>::generate_proof(
    const libsnark::protoboard<libff::Fr<ppT>> &pb,
    const typename groth16_snark<ppT>::ProvingKeyT &proving_key)
{
    libsnark::r1cs_primary_input<libff::Fr<ppT>> primary_input =
        pb.primary_input();
    libsnark::r1cs_auxiliary_input<libff::Fr<ppT>> auxiliary_input =
        pb.auxiliary_input();

    // Generate proof from public input, auxiliary input and proving key.
    // For now, force a pow2 domain, in case the key came from the MPC.
    libsnark::r1cs_gg_ppzksnark_proof<ppT> proof =
        libsnark::r1cs_gg_ppzksnark_prover(
            proving_key, primary_input, auxiliary_input, true);

    return proof;
}

template<typename ppT>
bool groth16_snark<ppT>::verify(
    const libsnark::r1cs_primary_input<libff::Fr<ppT>> &primary_inputs,
    const groth16_snark<ppT>::ProofT &proof,
    const groth16_snark<ppT>::VerifKeyT &verification_key)
{
    return libsnark::r1cs_gg_ppzksnark_verifier_strong_IC<ppT>(
        verification_key, primary_inputs, proof);
}

template<typename ppT>
void groth16_snark<ppT>::export_verification_key(
    const groth16_snark<ppT>::KeypairT &keypair)
{
    unsigned abc_length = keypair.vk.ABC_g1.rest.indices.size() + 1;

    std::cout << "\tVerification key in Solidity compliant format:{"
              << "\n"
              << "\t\tvk.alpha = Pairing.G1Point("
              << point_g1_affine_to_hex<ppT>(keypair.vk.alpha_g1) << ");"
              << "\n"
              << "\t\tvk.beta = Pairing.G2Point("
              << point_g2_affine_to_hex<ppT>(keypair.vk.beta_g2) << ");"
              << "\n"
              << "\t\tvk.delta = Pairing.G2Point("
              << point_g2_affine_to_hex<ppT>(keypair.vk.delta_g2) << ");"
              << "\n"
              << "\t\tvk.ABC = new Pairing.G1Point[](" << abc_length << ");"
              << "\n"
              << "\t\tvk.ABC[0] = Pairing.G1Point("
              << point_g1_affine_to_hex<ppT>(keypair.vk.ABC_g1.first) << ");"
              << "\n";
    for (size_t i = 1; i < abc_length; ++i) {
        auto vk_abc_i =
            point_g1_affine_to_hex<ppT>(keypair.vk.ABC_g1.rest.values[i - 1]);
        std::cout << "\t\tvk.ABC[" << i << "] = Pairing.G1Point(" << vk_abc_i
                  << ");"
                  << "\n";
    }
    // We flush std::cout only once at the end of the function
    std::cout << "\t\t}" << std::endl;
}

template<typename ppT>
void groth16_snark<ppT>::display_proof(
    const typename groth16_snark<ppT>::ProofT &proof)
{
    std::cout << "Proof:"
              << "\n"
              << "proof.A = Pairing.G1Point("
              << point_g1_affine_to_hex<ppT>(proof.g_A) << ");"
              << "\n"
              << "proof.B = Pairing.G2Point("
              << point_g2_affine_to_hex<ppT>(proof.g_B) << ");"
              << "\n"
              << "proof.C = Pairing.G1Point("
              << point_g1_affine_to_hex<ppT>(proof.g_C)
              // We flush std::cout only once at the end of the function
              << ");" << std::endl;
}

template<typename ppT>
void groth16_snark<ppT>::verification_key_to_json(
    const typename groth16_snark<ppT>::VerifKeyT &vk,
    boost::filesystem::path path)
{
    if (path.empty()) {
        boost::filesystem::path tmp_path = get_path_to_setup_directory();
        boost::filesystem::path vk_json_file("vk.json");
        path = tmp_path / vk_json_file;
    }
    // Convert boost path to char*
    const char *str_path = path.string().c_str();

    std::stringstream ss;
    std::ofstream fh;
    fh.open(str_path, std::ios::binary);
    unsigned abc_length = vk.ABC_g1.rest.indices.size() + 1;

    ss << "{"
       << "\n"
       << "\t\"alpha\""
       << " :[" << point_g1_affine_to_hex<ppT>(vk.alpha_g1) << "],"
       << "\n"
       << "\t\"beta\""
       << " :[" << point_g2_affine_to_hex<ppT>(vk.beta_g2) << "],"
       << "\n"
       << "\t\"delta\""
       << " :[" << point_g2_affine_to_hex<ppT>(vk.delta_g2) << "],"
       << "\n";
    ss << "\t\"ABC\""
       << " :[[" << point_g1_affine_to_hex<ppT>(vk.ABC_g1.first) << "]";
    for (size_t i = 1; i < abc_length; ++i) {
        auto vk_abc_i =
            point_g1_affine_to_hex<ppT>(vk.ABC_g1.rest.values[i - 1]);
        ss << ",[" << vk_abc_i << "]";
    }
    ss << "]"
       << "\n";
    ss << "}";

    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();
}

template<typename ppT>
void groth16_snark<ppT>::proof_and_inputs_to_json(
    const typename groth16_snark<ppT>::ProofT &proof,
    const libsnark::r1cs_primary_input<libff::Fr<ppT>> &input,
    boost::filesystem::path path)
{
    if (path.empty()) {
        // Used for debugging
        boost::filesystem::path tmp_path = get_path_to_debug_directory();
        boost::filesystem::path proof_and_inputs_json_file(
            "proof_and_inputs.json");
        path = tmp_path / proof_and_inputs_json_file;
    }

    // Convert the boost path into char*
    const char *str_path = path.string().c_str();

    std::stringstream ss;
    std::ofstream fh;
    fh.open(str_path, std::ios::binary);

    ss << "{"
       << "\n"
       << "\t\"a\" :[" << point_g1_affine_to_hex<ppT>(proof.g_A) << "],"
       << "\n"
       << "\t\"b\" :[" << point_g2_affine_to_hex<ppT>(proof.g_B) << "],"
       << "\n"
       << "\t\"c\" :[" << point_g1_affine_to_hex<ppT>(proof.g_C) << "],"
       << "\n"
       << "\t\"inputs\" :[";
    for (size_t i = 0; i < input.size(); ++i) {
        ss << "\"0x" << bigint_to_hex<libff::Fr<ppT>>(input[i].as_bigint())
           << "\"";
        if (i < input.size() - 1) {
            ss << ", ";
        }
    }
    ss << "]"
       << "\n";
    ss << "}";

    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();
}

template<typename ppT>
void groth16_snark<ppT>::proof_to_json(
    const typename groth16_snark<ppT>::ProofT &proof,
    boost::filesystem::path path)
{
    if (path.empty()) {
        // Used for a debugging purpose
        boost::filesystem::path tmp_path = get_path_to_debug_directory();
        boost::filesystem::path proof_json_file("proof.json");
        path = tmp_path / proof_json_file;
    }
    // Convert the boost path into char*
    const char *str_path = path.string().c_str();

    std::stringstream ss;
    std::ofstream fh;
    fh.open(str_path, std::ios::binary);

    ss << "{"
       << "\n"
       << "\t\"a\" :[" << point_g1_affine_to_hex<ppT>(proof.g_A) << "],"
       << "\n"
       << "\t\"b\" :[" << point_g2_affine_to_hex<ppT>(proof.g_B) << "],"
       << "\n"
       << "\t\"c\" :[" << point_g1_affine_to_hex<ppT>(proof.g_C) << "],"
       << "\n"
       << "}";

    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();
}

template<typename ppT>
void groth16_snark<ppT>::write_keypair(
    std::ostream &out, const typename groth16_snark<ppT>::KeypairT &keypair)
{
    if (!is_well_formed<ppT>(keypair.pk)) {
        throw std::invalid_argument("proving key (write) not well-formed");
    }
    if (!is_well_formed<ppT>(keypair.vk)) {
        throw std::invalid_argument("verification key (write) not well-formed");
    }
    out << keypair.pk;
    out << keypair.vk;
}

template<typename ppT>
typename groth16_snark<ppT>::KeypairT groth16_snark<ppT>::read_keypair(
    std::istream &in)
{
    libsnark::r1cs_gg_ppzksnark_keypair<ppT> keypair;
    in >> keypair.pk;
    in >> keypair.vk;
    if (!is_well_formed<ppT>(keypair.pk)) {
        throw std::invalid_argument("proving key (read) not well-formed");
    }
    if (!is_well_formed<ppT>(keypair.vk)) {
        throw std::invalid_argument("verification key (read) not well-formed");
    }
    return keypair;
}

template<typename ppT>
bool is_well_formed(const typename groth16_snark<ppT>::ProvingKeyT &pk)
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
bool is_well_formed(const typename groth16_snark<ppT>::VerifKeyT &vk)
{
    if (!vk.alpha_g1.is_well_formed() || !vk.beta_g2.is_well_formed() ||
        !vk.delta_g2.is_well_formed() || !vk.ABC_g1.first.is_well_formed()) {
        return false;
    }

    return container_is_well_formed(vk.ABC_g1.rest.values);
}

} // namespace libzeth

#endif // __ZETH_SNARKS_GROTH16_GROTH16_SNARK_TCC__
