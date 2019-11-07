#ifndef __ZETH_HELPER_TCC__
#define __ZETH_HELPER_TCC__

namespace libzeth
{
template<typename ppT>
void export_verification_key(libsnark::r1cs_ppzksnark_keypair<ppT> keypair)
{
    unsigned ic_length = keypair.vk.encoded_IC_query.rest.indices.size() + 1;

    std::cout << "\tVerification key in Solidity compliant format:{"
            << "\n"
            << "\t\tvk.A = Pairing.G2Point("
            << get_point_g2_affine_as_hex_str(keypair.vk.alphaA_g2)
            << ");" << "\n"
            << "\t\tvk.B = Pairing.G1Point("
            << get_point_g1_affine_as_hex_str(keypair.vk.alphaB_g1)
            << ");" << "\n"
            << "\t\tvk.C = Pairing.G2Point("
            << get_point_g2_affine_as_hex_str(keypair.vk.alphaC_g2)
            << ");" << "\n"
            << "\t\tvk.gamma = Pairing.G2Point("
            << get_point_g2_affine_as_hex_str(keypair.vk.gamma_g2)
            << ");" << "\n"
            << "\t\tvk.gammaBeta1 = Pairing.G1Point("
            << get_point_g1_affine_as_hex_str(keypair.vk.gamma_beta_g1)
            << ");" << "\n"
            << "\t\tvk.gammaBeta2 = Pairing.G2Point("
            << get_point_g2_affine_as_hex_str(keypair.vk.gamma_beta_g2)
            << ");" << "\n"
            << "\t\tvk.Z = Pairing.G2Point("
            << get_point_g2_affine_as_hex_str(keypair.vk.rC_Z_g2)
            << ");" << "\n"
            << "\t\tvk.IC = new Pairing.G1Point[](" << ic_length << ");"
            << "\t\tvk.IC[0] = Pairing.G1Point("
            << get_point_g1_affine_as_hex_str(keypair.vk.encoded_IC_query.first)
            << ");" << std::endl;
    for (size_t i = 1; i < ic_length; ++i) {
        auto vk_ic_i = get_point_g1_affine_as_hex_str(
            keypair.vk.encoded_IC_query.rest.values[i - 1]);
        std::cout << "\t\tvk.IC[" << i << "] = Pairing.G1Point(" << vk_ic_i
                  << ");" << std::endl;
    }
    std::cout << "\t\t}" << std::endl;
};

template<typename ppT>
void display_proof(libsnark::r1cs_ppzksnark_proof<ppT> proof)
{
    std::cout << "Proof:" 
            << "\n"
            << "proof.A = Pairing.G1Point("
            << get_point_g1_affine_as_hex_str(proof.g_A.g)
            << ");" << "\n"
            << "proof.A_p = Pairing.G1Point("
            << get_point_g1_affine_as_hex_str(proof.g_A.h)
            << ");" << "\n"
            << "proof.B = Pairing.G2Point("
            << get_point_g2_affine_as_hex_str(proof.g_B.g)
            << ");" << "\n"
            << "proof.B_p = Pairing.G1Point("
            << get_point_g1_affine_as_hex_str(proof.g_B.h)
            << ");" << "\n"
            << "proof.C = Pairing.G1Point("
            << get_point_g1_affine_as_hex_str(proof.g_C.g)
            << ");" << "\n"
            << "proof.C_p = Pairing.G1Point("
            << get_point_g1_affine_as_hex_str(proof.g_C.h)
            << ");" << "\n"
            << "proof.H = Pairing.G1Point("
            << get_point_g1_affine_as_hex_str(proof.g_H)
            << ");" << "\n"
            << "proof.K = Pairing.G1Point("
            << get_point_g1_affine_as_hex_str(proof.g_K)
            << ");" << std::endl;
};

template<typename ppT>
void verification_key_to_json(
    libsnark::r1cs_ppzksnark_verification_key<ppT> vk,
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
    unsigned ic_length = vk.encoded_IC_query.rest.indices.size() + 1;

    ss << "{\n";
    ss << " \"a\" :[" << get_point_g2_affine_as_hex_str(vk.alphaA_g2) << "],\n";
    ss << " \"b\"  :[" << get_point_g1_affine_as_hex_str(vk.alphaB_g1) << "],\n";
    ss << " \"c\" :[" << get_point_g2_affine_as_hex_str(vk.alphaC_g2) << "],\n";
    ss << " \"g\" :[" << get_point_g2_affine_as_hex_str(vk.gamma_g2) << "],\n";
    ss << " \"gb1\" :[" << get_point_g1_affine_as_hex_str(vk.gamma_beta_g1) << "],\n";
    ss << " \"gb2\" :[" << get_point_g2_affine_as_hex_str(vk.gamma_beta_g2) << "],\n";
    ss << " \"z\" :[" << get_point_g2_affine_as_hex_str(vk.rC_Z_g2) << "],\n";

    ss << "\"IC\" :[[" << get_point_g1_affine_as_hex_str(vk.encoded_IC_query.first)
       << "]";

    for (size_t i = 1; i < ic_length; ++i) {
        auto vk_ic_i =
            get_point_g1_affine_as_hex_str(vk.encoded_IC_query.rest.values[i - 1]);
        ss << ",[" << vk_ic_i << "]";
    }

    ss << "]";
    ss << "}";
    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();
};

template<typename ppT>
void proof_to_json(
    libsnark::r1cs_ppzksnark_proof<ppT> proof, boost::filesystem::path path)
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
    ss << " \"a\" :[" << get_point_g1_affine_as_hex_str(proof.g_A.g) << "],\n";
    ss << " \"a_p\"  :[" << get_point_g1_affine_as_hex_str(proof.g_A.h) << "],\n";
    ss << " \"b\"  :[" << get_point_g2_affine_as_hex_str(proof.g_B.g) << "],\n";
    ss << " \"b_p\" :[" << get_point_g1_affine_as_hex_str(proof.g_B.h) << "],\n";
    ss << " \"c\" :[" << get_point_g1_affine_as_hex_str(proof.g_C.g) << "],\n";
    ss << " \"c_p\" :[" << get_point_g1_affine_as_hex_str(proof.g_C.h) << "],\n";
    ss << " \"h\" :[" << get_point_g1_affine_as_hex_str(proof.g_H) << "],\n";
    ss << " \"k\" :[" << get_point_g1_affine_as_hex_str(proof.g_K) << "]\n";
    ss << "}";

    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();
};

template<typename ppT>
void proof_and_inputs_to_json(
    libsnark::r1cs_ppzksnark_proof<ppT> proof,
    libsnark::r1cs_ppzksnark_primary_input<ppT> input,
    boost::filesystem::path path)
{
    if (path.empty()) {
        // Used for debugging purpose
        boost::filesystem::path tmp_path = get_path_to_debug_directory();
        boost::filesystem::path proof_and_input_json_file("proof_and_input.json");
        path = tmp_path / proof_and_input_json_file;
    }
    // Convert the boost path into char*
    const char *str_path = path.string().c_str();

    std::stringstream ss;
    std::ofstream fh;
    fh.open(str_path, std::ios::binary);

    ss << "{\n";
    ss << " \"a\" :[" << get_point_g1_affine_as_hex_str(proof.g_A.g) << "],\n";
    ss << " \"a_p\"  :[" << get_point_g1_affine_as_hex_str(proof.g_A.h) << "],\n";
    ss << " \"b\"  :[" << get_point_g2_affine_as_hex_str(proof.g_B.g) << "],\n";
    ss << " \"b_p\" :[" << get_point_g1_affine_as_hex_str(proof.g_B.h) << "],\n";
    ss << " \"c\" :[" << get_point_g1_affine_as_hex_str(proof.g_C.g) << "],\n";
    ss << " \"c_p\" :[" << get_point_g1_affine_as_hex_str(proof.g_C.h) << "],\n";
    ss << " \"h\" :[" << get_point_g1_affine_as_hex_str(proof.g_H) << "],\n";
    ss << " \"k\" :[" << get_point_g1_affine_as_hex_str(proof.g_K) << "],\n";
    ss << " \"input\" :"
       << "["; // 1 should always be the first variable passed
    for (size_t i = 0; i < input.size(); ++i) {
        ss << "\"0x" << hex_string_from_libsnark_bigint(input[i].as_bigint())
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
};
} // namespace libzeth

#endif // __ZETH_HELPERS_TCC__
