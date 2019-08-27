#ifndef __ZETH_HELPER_TCC__
#define __ZETH_HELPER_TCC__

namespace libzeth
{

template<typename ppT>
void exportVerificationKey(libsnark::r1cs_gg_ppzksnark_keypair<ppT> keypair)
{
    unsigned gammaABCLength = keypair.vk.gamma_ABC_g1.rest.indices.size() + 1;

    std::cout << "\tVerification key in Solidity compliant format:{"
              << std::endl;
    std::cout << "\t\tvk.alpha = Pairing.G1Point("
              << outputPointG1AffineAsHex(keypair.vk.alpha_g1) << ");"
              << std::endl;
    std::cout << "\t\tvk.beta = Pairing.G2Point("
              << outputPointG2AffineAsHex(keypair.vk.beta_g2) << ");"
              << std::endl;
    std::cout << "\t\tvk.gamma = Pairing.G2Point("
              << outputPointG2AffineAsHex(keypair.vk.gamma_g2) << ");"
              << std::endl;
    std::cout << "\t\tvk.delta = Pairing.G2Point("
              << outputPointG2AffineAsHex(keypair.vk.delta_g2) << ");"
              << std::endl;
    std::cout << "\t\tvk.GammaABC = new Pairing.G1Point[](" << gammaABCLength
              << ");" << std::endl;
    std::cout << "\t\tvk.GammaABC[0] = Pairing.G1Point("
              << outputPointG1AffineAsHex(keypair.vk.gamma_ABC_g1.first) << ");"
              << std::endl;
    for (size_t i = 1; i < gammaABCLength; ++i) {
        auto vkGammaABCi = outputPointG1AffineAsHex(
            keypair.vk.gamma_ABC_g1.rest.values[i - 1]);
        std::cout << "\t\tvk.gammaABC[" << i << "] = Pairing.G1Point("
                  << vkGammaABCi << ");" << std::endl;
    }

    std::cout << "\t\t}" << std::endl;
};

template<typename ppT>
void displayProof(libsnark::r1cs_gg_ppzksnark_proof<ppT> proof)
{
    std::cout << "Proof:" << std::endl;
    std::cout << "proof.A = Pairing.G1Point("
              << outputPointG1AffineAsHex(proof.g_A) << ");" << std::endl;
    std::cout << "proof.B = Pairing.G2Point("
              << outputPointG2AffineAsHex(proof.g_B) << ");" << std::endl;
    std::cout << "proof.C = Pairing.G1Point("
              << outputPointG1AffineAsHex(proof.g_C) << ");" << std::endl;
};

template<typename ppT>
void verificationKeyToJson(
    libsnark::r1cs_gg_ppzksnark_verification_key<ppT> vk,
    boost::filesystem::path path)
{
    if (path.empty()) {
        boost::filesystem::path tmp_path = getPathToSetupDir();
        boost::filesystem::path vkey_json("vk.json");
        path = tmp_path / vkey_json;
    }
    // Convert boost path to char*
    const char *str_path = path.string().c_str();

    std::stringstream ss;
    std::ofstream fh;
    fh.open(str_path, std::ios::binary);
    unsigned gammaABCLength = vk.gamma_ABC_g1.rest.indices.size() + 1;

    ss << "{\n";
    ss << " \"alpha\"  :[" << outputPointG1AffineAsHex(vk.alpha_g1) << "],\n";
    ss << " \"beta\"  :[" << outputPointG2AffineAsHex(vk.beta_g2) << "],\n";
    ss << " \"gamma\"  :[" << outputPointG2AffineAsHex(vk.gamma_g2) << "],\n";
    ss << " \"delta\" :[" << outputPointG2AffineAsHex(vk.delta_g2) << "],\n";

    ss << "\"gammaABC\" :[[" << outputPointG1AffineAsHex(vk.gamma_ABC_g1.first)
       << "]";

    for (size_t i = 1; i < gammaABCLength; ++i) {
        auto vkGammaABCi =
            outputPointG1AffineAsHex(vk.gamma_ABC_g1.rest.values[i - 1]);
        ss << ",[" << vkGammaABCi << "]";
    }

    ss << "]";
    ss << "}";
    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();
};

template<typename ppT>
void proofToJson(
    libsnark::r1cs_gg_ppzksnark_proof<ppT> proof, boost::filesystem::path path)
{
    if (path.empty()) {
        boost::filesystem::path tmp_path =
            getPathToDebugDir(); // Used for a debug purpose
        boost::filesystem::path proof_json("proof.json");
        path = tmp_path / proof_json;
    }
    // Convert the boost path into char*
    const char *str_path = path.string().c_str();

    std::stringstream ss;
    std::ofstream fh;
    fh.open(str_path, std::ios::binary);

    ss << "{\n";
    ss << " \"a\" :[" << outputPointG1AffineAsHex(proof.g_A) << "],\n";
    ss << " \"b\"  :[" << outputPointG2AffineAsHex(proof.g_B) << "],\n";
    ss << " \"c\" :[" << outputPointG1AffineAsHex(proof.g_C) << "],\n";
    ss << "}";

    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();
};

template<typename ppT>
void proofAndInputToJson(
    libsnark::r1cs_gg_ppzksnark_proof<ppT> proof,
    libsnark::r1cs_ppzksnark_primary_input<ppT> input,
    boost::filesystem::path path)
{
    if (path.empty()) {
        boost::filesystem::path tmp_path =
            getPathToDebugDir(); // Used for a debug purpose
        boost::filesystem::path proof_and_input_json("proof_and_input.json");
        path = tmp_path / proof_and_input_json;
    }
    // Convert the boost path into char*
    const char *str_path = path.string().c_str();

    std::stringstream ss;
    std::ofstream fh;
    fh.open(str_path, std::ios::binary);

    ss << "{\n";
    ss << " \"a\" :[" << outputPointG1AffineAsHex(proof.g_A) << "],\n";
    ss << " \"b\"  :[" << outputPointG2AffineAsHex(proof.g_B) << "],\n";
    ss << " \"c\" :[" << outputPointG1AffineAsHex(proof.g_C) << "],\n";
    ss << " \"input\" :"
       << "["; // 1 should always be the first variable passed

    for (size_t i = 0; i < input.size(); ++i) {
        ss << "\"0x" << HexStringFromLibsnarkBigint(input[i].as_bigint())
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
