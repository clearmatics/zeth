/**
 * File modified from:
 *
 * @file wraplibsnark.cpp
 * @author Jacob Eberhardt <jacob.eberhardt@tu-berlin.de
 * @author Dennis Kuhnert <dennis.kuhnert@campus.tu-berlin.de>
 * @date 2017
 */

#include "libsnark_helpers.hpp"

typedef long integer_coeff_t;

using namespace std;
using namespace libsnark;

// Conversion byte[32] <-> libsnark bigint.
libff::bigint<libff::alt_bn128_r_limbs> libsnarkBigintFromBytes(const uint8_t* _x) {
    libff::bigint<libff::alt_bn128_r_limbs> x;

    for (unsigned i = 0; i < 4; i++) {
        for (unsigned j = 0; j < 8; j++) {
            x.data[3 - i] |= uint64_t(_x[i * 8 + j]) << (8 * (7-j));
        }
    }
    return x;
}

std::string HexStringFromLibsnarkBigint(libff::bigint<libff::alt_bn128_r_limbs> _x) {
    uint8_t x[32];
    for (unsigned i = 0; i < 4; i++)
        for (unsigned j = 0; j < 8; j++)
            x[i * 8 + j] = uint8_t(uint64_t(_x.data[3 - i]) >> (8 * (7 - j)));

    std::stringstream ss;
    ss << std::setfill('0');
    for (unsigned i = 0; i<32; i++) {
        ss << std::hex << std::setw(2) << (int)x[i];
    }

std:string str = ss.str();
    return str.erase(0, min(str.find_first_not_of('0'), str.size()-1));
}

std::string outputPointG1AffineAsHex(libff::alt_bn128_G1 _p) {
    libff::alt_bn128_G1 aff = _p;
    aff.to_affine_coordinates();
    return
        "\"0x" +
        HexStringFromLibsnarkBigint(aff.X.as_bigint()) +
        "\", \"0x" +
        HexStringFromLibsnarkBigint(aff.Y.as_bigint()) +
        "\"";
}

std::string outputPointG2AffineAsHex(libff::alt_bn128_G2 _p) {
    libff::alt_bn128_G2 aff = _p;
    aff.to_affine_coordinates();
    return
        "[\"0x" +
        HexStringFromLibsnarkBigint(aff.X.c1.as_bigint()) + "\", \"0x" +
        HexStringFromLibsnarkBigint(aff.X.c0.as_bigint()) + "\"],\n [\"0x" +
        HexStringFromLibsnarkBigint(aff.Y.c1.as_bigint()) + "\", \"0x" +
        HexStringFromLibsnarkBigint(aff.Y.c0.as_bigint()) + "\"]";
}

boost::filesystem::path getPathToSetupDir() {
    char* pathToSetupFolder;
    pathToSetupFolder = std::getenv("ZETH_TRUSTED_SETUP_DIR");
    if (pathToSetupFolder == NULL) {
        // Fallback destination if the ZETH_TRUSTED_SETUP_DIR env var is not set
        pathToSetupFolder = "../trusted_setup";
    }
    boost::filesystem::path setup_dir(pathToSetupFolder);
    return setup_dir;
}

boost::filesystem::path getPathToDebugDir() {
    char* pathToDebugFolder;
    pathToDebugFolder = std::getenv("ZETH_DEBUG_DIR");
    if (pathToDebugFolder == NULL) {
        // Fallback destination if the ZETH_DEBUG_DIR env var is not set
        pathToDebugFolder = "../debug";
    }
    boost::filesystem::path setup_dir(pathToDebugFolder);
    return setup_dir;
}

// Generate keypair (proving key, verif key) from constraints
r1cs_ppzksnark_keypair<libff::alt_bn128_pp> generateKeypair(const r1cs_ppzksnark_constraint_system<libff::alt_bn128_pp> &cs){
    // From r1cs_ppzksnark.hpp
    return r1cs_ppzksnark_generator<libff::alt_bn128_pp>(cs);
}

void serializeProvingKeyToFile(r1cs_ppzksnark_proving_key<libff::alt_bn128_pp> pk, boost::filesystem::path pk_path){
    writeToFile(pk_path, pk);
}

r1cs_ppzksnark_proving_key<libff::alt_bn128_pp> deserializeProvingKeyFromFile(boost::filesystem::path pk_path){
    return loadFromFile<r1cs_ppzksnark_proving_key<libff::alt_bn128_pp>>(pk_path);
}

void serializeVerificationKeyToFile(r1cs_ppzksnark_verification_key<libff::alt_bn128_pp> vk, boost::filesystem::path vk_path){
    writeToFile(vk_path, vk);
}

r1cs_ppzksnark_verification_key<libff::alt_bn128_pp> deserializeVerificationKeyFromFile(boost::filesystem::path vk_path){
    return loadFromFile<r1cs_ppzksnark_verification_key<libff::alt_bn128_pp>>(vk_path);
}

void exportVerificationKey(r1cs_ppzksnark_keypair<libff::alt_bn128_pp> keypair){
    unsigned icLength = keypair.vk.encoded_IC_query.rest.indices.size() + 1;

    cout << "\tVerification key in Solidity compliant format:{" << endl;
    cout << "\t\tvk.A = Pairing.G2Point(" << outputPointG2AffineAsHex(keypair.vk.alphaA_g2) << ");" << endl;
    cout << "\t\tvk.B = Pairing.G1Point(" << outputPointG1AffineAsHex(keypair.vk.alphaB_g1) << ");" << endl;
    cout << "\t\tvk.C = Pairing.G2Point(" << outputPointG2AffineAsHex(keypair.vk.alphaC_g2) << ");" << endl;
    cout << "\t\tvk.gamma = Pairing.G2Point(" << outputPointG2AffineAsHex(keypair.vk.gamma_g2) << ");" << endl;
    cout << "\t\tvk.gammaBeta1 = Pairing.G1Point(" << outputPointG1AffineAsHex(keypair.vk.gamma_beta_g1) << ");" << endl;
    cout << "\t\tvk.gammaBeta2 = Pairing.G2Point(" << outputPointG2AffineAsHex(keypair.vk.gamma_beta_g2) << ");" << endl;
    cout << "\t\tvk.Z = Pairing.G2Point(" << outputPointG2AffineAsHex(keypair.vk.rC_Z_g2) << ");" << endl;
    cout << "\t\tvk.IC = new Pairing.G1Point[](" << icLength << ");" << endl;
    cout << "\t\tvk.IC[0] = Pairing.G1Point(" << outputPointG1AffineAsHex(keypair.vk.encoded_IC_query.first) << ");" << endl;
    for (size_t i = 1; i < icLength; ++i) {
        auto vkICi = outputPointG1AffineAsHex(keypair.vk.encoded_IC_query.rest.values[i - 1]);
        cout << "\t\tvk.IC[" << i << "] = Pairing.G1Point(" << vkICi << ");" << endl;
    }
    cout << "\t\t}" << endl;
}

void printProof(r1cs_ppzksnark_proof<libff::alt_bn128_pp> proof){
    cout << "Proof:"<< endl;
    cout << "proof.A = Pairing.G1Point(" << outputPointG1AffineAsHex(proof.g_A.g)<< ");" << endl;
    cout << "proof.A_p = Pairing.G1Point(" << outputPointG1AffineAsHex(proof.g_A.h)<< ");" << endl;
    cout << "proof.B = Pairing.G2Point(" << outputPointG2AffineAsHex(proof.g_B.g)<< ");" << endl;
    cout << "proof.B_p = Pairing.G1Point(" << outputPointG1AffineAsHex(proof.g_B.h)<<");" << endl;
    cout << "proof.C = Pairing.G1Point(" << outputPointG1AffineAsHex(proof.g_C.g)<< ");" << endl;
    cout << "proof.C_p = Pairing.G1Point(" << outputPointG1AffineAsHex(proof.g_C.h)<<");" << endl;
    cout << "proof.H = Pairing.G1Point(" << outputPointG1AffineAsHex(proof.g_H)<<");"<< endl;
    cout << "proof.K = Pairing.G1Point(" << outputPointG1AffineAsHex(proof.g_K)<<");"<< endl;
}

void verificationKey_to_json(r1cs_ppzksnark_keypair<libff::alt_bn128_pp> keypair, boost::filesystem::path path) {
    // Convert boost path to char*
    const char* str_path = path.string().c_str();

    std::stringstream ss;
    std::ofstream fh;
    fh.open(str_path, std::ios::binary);
    unsigned icLength = keypair.vk.encoded_IC_query.rest.indices.size() + 1;

    ss << "{\n";
    ss << " \"a\" :[" << outputPointG2AffineAsHex(keypair.vk.alphaA_g2) << "],\n";
    ss << " \"b\"  :[" << outputPointG1AffineAsHex(keypair.vk.alphaB_g1) << "],\n";
    ss << " \"c\" :[" << outputPointG2AffineAsHex(keypair.vk.alphaC_g2) << "],\n";
    ss << " \"g\" :[" << outputPointG2AffineAsHex(keypair.vk.gamma_g2)<< "],\n";
    ss << " \"gb1\" :[" << outputPointG1AffineAsHex(keypair.vk.gamma_beta_g1)<< "],\n";
    ss << " \"gb2\" :[" << outputPointG2AffineAsHex(keypair.vk.gamma_beta_g2)<< "],\n";
    ss << " \"z\" :[" << outputPointG2AffineAsHex(keypair.vk.rC_Z_g2)<< "],\n";

    ss <<  "\"IC\" :[[" << outputPointG1AffineAsHex(keypair.vk.encoded_IC_query.first) << "]";

    for (size_t i = 1; i < icLength; ++i) {
        auto vkICi = outputPointG1AffineAsHex(keypair.vk.encoded_IC_query.rest.values[i - 1]);
        ss << ",[" <<  vkICi << "]";
    }

    ss << "]";
    ss << "}";
    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();
}

bool replace(std::string& str, const std::string& from, const std::string& to) {
    size_t start_pos = str.find(from);
    if(start_pos == std::string::npos) {
        return false;
    }
    str.replace(start_pos, from.length(), to);
    return true;
}
