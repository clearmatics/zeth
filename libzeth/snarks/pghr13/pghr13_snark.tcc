// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SNARKS_PGHR13_PGHR13_SNARK_TCC__
#define __ZETH_SNARKS_PGHR13_PGHR13_SNARK_TCC__

#include "libzeth/core/field_element_utils.hpp"
#include "libzeth/serialization/filesystem_util.hpp" // TODO: remove this
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
    const pghr13_snark<ppT>::VerifKeyT &verification_key)
{
    return libsnark::r1cs_ppzksnark_verifier_strong_IC<ppT>(
        verification_key, primary_inputs, proof);
}

template<typename ppT>
void pghr13_snark<ppT>::export_verification_key(
    const pghr13_snark<ppT>::KeypairT &keypair)
{
    unsigned ic_length = keypair.vk.encoded_IC_query.rest.indices.size() + 1;

    std::cout << "\tVerification key in Solidity compliant format:{"
              << "\n"
              << "\t\tvk.A = Pairing.G2Point("
              << point_g2_affine_to_hex<ppT>(keypair.vk.alphaA_g2) << ");"
              << "\n"
              << "\t\tvk.B = Pairing.G1Point("
              << point_g1_affine_to_hex<ppT>(keypair.vk.alphaB_g1) << ");"
              << "\n"
              << "\t\tvk.C = Pairing.G2Point("
              << point_g2_affine_to_hex<ppT>(keypair.vk.alphaC_g2) << ");"
              << "\n"
              << "\t\tvk.gamma = Pairing.G2Point("
              << point_g2_affine_to_hex<ppT>(keypair.vk.gamma_g2) << ");"
              << "\n"
              << "\t\tvk.gammaBeta1 = Pairing.G1Point("
              << point_g1_affine_to_hex<ppT>(keypair.vk.gamma_beta_g1) << ");"
              << "\n"
              << "\t\tvk.gammaBeta2 = Pairing.G2Point("
              << point_g2_affine_to_hex<ppT>(keypair.vk.gamma_beta_g2) << ");"
              << "\n"
              << "\t\tvk.Z = Pairing.G2Point("
              << point_g2_affine_to_hex<ppT>(keypair.vk.rC_Z_g2) << ");"
              << "\n"
              << "\t\tvk.IC = new Pairing.G1Point[](" << ic_length << ");"
              << "\t\tvk.IC[0] = Pairing.G1Point("
              << point_g1_affine_to_hex<ppT>(keypair.vk.encoded_IC_query.first)
              << ");" << std::endl;
    for (size_t i = 1; i < ic_length; ++i) {
        auto vk_ic_i = point_g1_affine_to_hex<ppT>(
            keypair.vk.encoded_IC_query.rest.values[i - 1]);
        std::cout << "\t\tvk.IC[" << i << "] = Pairing.G1Point(" << vk_ic_i
                  << ");" << std::endl;
    }
    std::cout << "\t\t}" << std::endl;
}

template<typename ppT>
void pghr13_snark<ppT>::display_proof(const pghr13_snark<ppT>::ProofT &proof)
{
    std::cout << "Proof:"
              << "\n"
              << "proof.A = Pairing.G1Point("
              << point_g1_affine_to_hex<ppT>(proof.g_A.g) << ");"
              << "\n"
              << "proof.A_p = Pairing.G1Point("
              << point_g1_affine_to_hex<ppT>(proof.g_A.h) << ");"
              << "\n"
              << "proof.B = Pairing.G2Point("
              << point_g2_affine_to_hex<ppT>(proof.g_B.g) << ");"
              << "\n"
              << "proof.B_p = Pairing.G1Point("
              << point_g1_affine_to_hex<ppT>(proof.g_B.h) << ");"
              << "\n"
              << "proof.C = Pairing.G1Point("
              << point_g1_affine_to_hex<ppT>(proof.g_C.g) << ");"
              << "\n"
              << "proof.C_p = Pairing.G1Point("
              << point_g1_affine_to_hex<ppT>(proof.g_C.h) << ");"
              << "\n"
              << "proof.H = Pairing.G1Point("
              << point_g1_affine_to_hex<ppT>(proof.g_H) << ");"
              << "\n"
              << "proof.K = Pairing.G1Point("
              << point_g1_affine_to_hex<ppT>(proof.g_K) << ");" << std::endl;
}

template<typename ppT>
void pghr13_snark<ppT>::verification_key_to_json(
    const pghr13_snark<ppT>::VerifKeyT &vk, boost::filesystem::path path)
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
    unsigned ic_length = vk.encoded_IC_query.rest.indices.size() + 1;

    ss << "{\n";
    ss << " \"a\" :[" << point_g2_affine_to_hex<ppT>(vk.alphaA_g2) << "],\n";
    ss << " \"b\"  :[" << point_g1_affine_to_hex<ppT>(vk.alphaB_g1) << "],\n";
    ss << " \"c\" :[" << point_g2_affine_to_hex<ppT>(vk.alphaC_g2) << "],\n";
    ss << " \"g\" :[" << point_g2_affine_to_hex<ppT>(vk.gamma_g2) << "],\n";
    ss << " \"gb1\" :[" << point_g1_affine_to_hex<ppT>(vk.gamma_beta_g1)
       << "],\n";
    ss << " \"gb2\" :[" << point_g2_affine_to_hex<ppT>(vk.gamma_beta_g2)
       << "],\n";
    ss << " \"z\" :[" << point_g2_affine_to_hex<ppT>(vk.rC_Z_g2) << "],\n";

    ss << "\"IC\" :[[" << point_g1_affine_to_hex<ppT>(vk.encoded_IC_query.first)
       << "]";

    for (size_t i = 1; i < ic_length; ++i) {
        auto vk_ic_i =
            point_g1_affine_to_hex<ppT>(vk.encoded_IC_query.rest.values[i - 1]);
        ss << ",[" << vk_ic_i << "]";
    }

    ss << "]";
    ss << "}";
    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();
}

template<typename ppT>
void pghr13_snark<ppT>::proof_and_inputs_to_json(
    const pghr13_snark<ppT>::ProofT &proof,
    const libsnark::r1cs_primary_input<libff::Fr<ppT>> &input,
    boost::filesystem::path path)
{
    if (path.empty()) {
        // Used for debugging purpose
        boost::filesystem::path tmp_path = get_path_to_debug_directory();
        boost::filesystem::path proof_and_input_json_file(
            "proof_and_input.json");
        path = tmp_path / proof_and_input_json_file;
    }
    // Convert the boost path into char*
    const char *str_path = path.string().c_str();

    std::stringstream ss;
    std::ofstream fh;
    fh.open(str_path, std::ios::binary);

    ss << "{\n";
    ss << " \"a\" :[" << point_g1_affine_to_hex<ppT>(proof.g_A.g) << "],\n";
    ss << " \"a_p\"  :[" << point_g1_affine_to_hex<ppT>(proof.g_A.h) << "],\n";
    ss << " \"b\"  :[" << point_g2_affine_to_hex<ppT>(proof.g_B.g) << "],\n";
    ss << " \"b_p\" :[" << point_g1_affine_to_hex<ppT>(proof.g_B.h) << "],\n";
    ss << " \"c\" :[" << point_g1_affine_to_hex<ppT>(proof.g_C.g) << "],\n";
    ss << " \"c_p\" :[" << point_g1_affine_to_hex<ppT>(proof.g_C.h) << "],\n";
    ss << " \"h\" :[" << point_g1_affine_to_hex<ppT>(proof.g_H) << "],\n";
    ss << " \"k\" :[" << point_g1_affine_to_hex<ppT>(proof.g_K) << "],\n";
    ss << " \"input\" :"
       << "["; // 1 should always be the first variable passed
    for (size_t i = 0; i < input.size(); ++i) {
        ss << "\"0x" << bigint_to_hex<libff::Fr<ppT>>(input[i].as_bigint())
           << "\"";
        if (i < input.size() - 1) {
            ss << ", ";
        }
    }
    ss << "]\n";
    ss << "}";

    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();
}

template<typename ppT>
void pghr13_snark<ppT>::proof_to_json(
    const pghr13_snark<ppT>::ProofT &proof, boost::filesystem::path path)
{
    if (path.empty()) {
        // Used for debugging purpose
        boost::filesystem::path tmp_path = get_path_to_debug_directory();
        boost::filesystem::path proof_json("proof.json");
        path = tmp_path / proof_json;
    }
    // Convert the boost path into char*
    const char *str_path = path.string().c_str();

    std::stringstream ss;
    std::ofstream fh;
    fh.open(str_path, std::ios::binary);

    ss << "{\n";
    ss << " \"a\" :[" << point_g1_affine_to_hex<ppT>(proof.g_A.g) << "],\n";
    ss << " \"a_p\"  :[" << point_g1_affine_to_hex<ppT>(proof.g_A.h) << "],\n";
    ss << " \"b\"  :[" << point_g2_affine_to_hex<ppT>(proof.g_B.g) << "],\n";
    ss << " \"b_p\" :[" << point_g1_affine_to_hex<ppT>(proof.g_B.h) << "],\n";
    ss << " \"c\" :[" << point_g1_affine_to_hex<ppT>(proof.g_C.g) << "],\n";
    ss << " \"c_p\" :[" << point_g1_affine_to_hex<ppT>(proof.g_C.h) << "],\n";
    ss << " \"h\" :[" << point_g1_affine_to_hex<ppT>(proof.g_H) << "],\n";
    ss << " \"k\" :[" << point_g1_affine_to_hex<ppT>(proof.g_K) << "]\n";
    ss << "}";

    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();
}

template<typename ppT>
void pghr13_snark<ppT>::write_keypair(
    std::ostream &out, const pghr13_snark<ppT>::KeypairT &keypair)
{
    out << keypair.pk;
    out << keypair.vk;
}

template<typename ppT>
typename pghr13_snark<ppT>::KeypairT pghr13_snark<ppT>::read_keypair(
    std::istream &in)
{
    pghr13_snark<ppT>::ProvingKeyT pk;
    pghr13_snark<ppT>::VerifKeyT vk;
    in >> pk;
    in >> vk;
    return pghr13_snark<ppT>::KeypairT(pk, vk);
}

} // namespace libzeth

#endif // __ZETH_SNARKS_PGHR13_PGHR13_SNARK_TCC__
