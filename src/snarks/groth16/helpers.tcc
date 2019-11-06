#ifndef __ZETH_HELPER_TCC__
#define __ZETH_HELPER_TCC__

namespace libzeth
{

template<typename ppT>
void export_verification_key(libsnark::r1cs_gg_ppzksnark_keypair<ppT> keypair)
{
    unsigned abc_length = keypair.vk.ABC_g1.rest.indices.size() + 1;

    std::cout << "\tVerification key in Solidity compliant format:{"
              << "\n"
              << "\t\tvk.alpha = Pairing.G1Point("
              << get_point_g1_affine_as_hex_str(keypair.vk.alpha_g1) << ");"
              << "\n"
              << "\t\tvk.beta = Pairing.G2Point("
              << get_point_g2_affine_as_hex_str(keypair.vk.beta_g2) << ");"
              << "\n"
              << "\t\tvk.delta = Pairing.G2Point("
              << get_point_g2_affine_as_hex_str(keypair.vk.delta_g2) << ");"
              << "\n"
              << "\t\tvk.ABC = new Pairing.G1Point[](" << abc_length << ");"
              << "\n"
              << "\t\tvk.ABC[0] = Pairing.G1Point("
              << get_point_g1_affine_as_hex_str(keypair.vk.ABC_g1.first) << ");"
              << "\n";
    for (size_t i = 1; i < abc_length; ++i) {
        auto vk_abc_i = get_point_g1_affine_as_hex_str(
            keypair.vk.ABC_g1.rest.values[i - 1]);
        std::cout << "\t\tvk.ABC[" << i << "] = Pairing.G1Point(" << vk_abc_i
                  << ");"
                  << "\n";
    }
    // We flush std::cout only once at the end of the function
    std::cout << "\t\t}" << std::endl;
};

template<typename ppT>
void display_proof(libsnark::r1cs_gg_ppzksnark_proof<ppT> proof)
{
    std::cout << "Proof:"
              << "\n"
              << "proof.A = Pairing.G1Point("
              << get_point_g1_affine_as_hex_str(proof.g_A) << ");"
              << "\n"
              << "proof.B = Pairing.G2Point("
              << get_point_g2_affine_as_hex_str(proof.g_B) << ");"
              << "\n"
              << "proof.C = Pairing.G1Point("
              << get_point_g1_affine_as_hex_str(proof.g_C)
              // We flush std::cout only once at the end of the function
              << ");" << std::endl;
};

template<typename ppT>
void verification_key_to_json(
    libsnark::r1cs_gg_ppzksnark_verification_key<ppT> vk,
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
       << " :[" << get_point_g1_affine_as_hex_str(vk.alpha_g1) << "],"
       << "\n"
       << "\t\"beta\""
       << " :[" << get_point_g2_affine_as_hex_str(vk.beta_g2) << "],"
       << "\n"
       << "\t\"delta\""
       << " :[" << get_point_g2_affine_as_hex_str(vk.delta_g2) << "],"
       << "\n";
    ss << "\t\"ABC\""
       << " :[[" << get_point_g1_affine_as_hex_str(vk.ABC_g1.first) << "]";
    for (size_t i = 1; i < abc_length; ++i) {
        auto vk_abc_i =
            get_point_g1_affine_as_hex_str(vk.ABC_g1.rest.values[i - 1]);
        ss << ",[" << vk_abc_i << "]";
    }
    ss << "]"
       << "\n";
    ss << "}";

    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();
};

template<typename ppT>
void proof_to_json(
    libsnark::r1cs_gg_ppzksnark_proof<ppT> proof, boost::filesystem::path path)
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
       << "\t\"a\" :[" << get_point_g1_affine_as_hex_str(proof.g_A) << "],"
       << "\n"
       << "\t\"b\" :[" << get_point_g2_affine_as_hex_str(proof.g_B) << "],"
       << "\n"
       << "\t\"c\" :[" << get_point_g1_affine_as_hex_str(proof.g_C) << "],"
       << "\n"
       << "}";

    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();
};

template<typename ppT>
void proof_and_inputs_to_json(
    libsnark::r1cs_gg_ppzksnark_proof<ppT> proof,
    libsnark::r1cs_ppzksnark_primary_input<ppT> input,
    boost::filesystem::path path)
{
    if (path.empty()) {
        // Used for a debugging purpose
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
       << "\t\"a\" :[" << get_point_g1_affine_as_hex_str(proof.g_A) << "],"
       << "\n"
       << "\t\"b\" :[" << get_point_g2_affine_as_hex_str(proof.g_B) << "],"
       << "\n"
       << "\t\"c\" :[" << get_point_g1_affine_as_hex_str(proof.g_C) << "],"
       << "\n"
       << "\t\"inputs\" :[";
    for (size_t i = 0; i < input.size(); ++i) {
        ss << "\"0x" << hex_string_from_libsnark_bigint(input[i].as_bigint())
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
};

} // namespace libzeth

#endif // __ZETH_HELPERS_TCC__
