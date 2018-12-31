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

//using namespace std;
//using namespace libsnark;

// Conversion byte[32] <-> libsnark bigint.
libff::bigint<libff::alt_bn128_r_limbs> libsnarkBigintFromBytes(const uint8_t* _x)
{
    libff::bigint<libff::alt_bn128_r_limbs> x;

    for (unsigned i = 0; i < 4; i++)
    {
        for (unsigned j = 0; j < 8; j++)
        {
            x.data[3 - i] |= uint64_t(_x[i * 8 + j]) << (8 * (7-j));
        }
    }
    return x;
}

std::string HexStringFromLibsnarkBigint(libff::bigint<libff::alt_bn128_r_limbs> _x)
{
    uint8_t x[32];
    for (unsigned i = 0; i < 4; i++)
    {
        for (unsigned j = 0; j < 8; j++)
        {
            x[i * 8 + j] = uint8_t(uint64_t(_x.data[3 - i]) >> (8 * (7 - j)));
        }
    }

    std::stringstream ss;
    ss << std::setfill('0');
    for (unsigned i = 0; i<32; i++)
    {
        ss << std::hex << std::setw(2) << (int)x[i];
    }

    std::string str = ss.str();
    return str.erase(0, min(str.find_first_not_of('0'), str.size()-1));
}

std::string outputPointG1AffineAsHex(libff::alt_bn128_G1 _p)
{
    libff::alt_bn128_G1 aff = _p;
    aff.to_affine_coordinates();
    return
        "\"0x" +
        HexStringFromLibsnarkBigint(aff.X.as_bigint()) +
        "\", \"0x" +
        HexStringFromLibsnarkBigint(aff.Y.as_bigint()) +
        "\"";
}

std::string outputPointG2AffineAsHex(libff::alt_bn128_G2 _p)
{
    libff::alt_bn128_G2 aff = _p;
    aff.to_affine_coordinates();
    return
        "[\"0x" +
        HexStringFromLibsnarkBigint(aff.X.c1.as_bigint()) + "\", \"0x" +
        HexStringFromLibsnarkBigint(aff.X.c0.as_bigint()) + "\"],\n [\"0x" +
        HexStringFromLibsnarkBigint(aff.Y.c1.as_bigint()) + "\", \"0x" +
        HexStringFromLibsnarkBigint(aff.Y.c0.as_bigint()) + "\"]";
}

boost::filesystem::path getPathToSetupDir()
{
    char* pathToSetupFolder;
    pathToSetupFolder = std::getenv("ZETH_TRUSTED_SETUP_DIR");
    if (pathToSetupFolder == NULL)
    {
        // Fallback destination if the ZETH_TRUSTED_SETUP_DIR env var is not set
        pathToSetupFolder = "../trusted_setup";
    }

    boost::filesystem::path setup_dir(pathToSetupFolder);
    return setup_dir;
}

boost::filesystem::path getPathToDebugDir()
{
    char* pathToDebugFolder;
    pathToDebugFolder = std::getenv("ZETH_DEBUG_DIR");
    if (pathToDebugFolder == NULL)
    {
        // Fallback destination if the ZETH_DEBUG_DIR env var is not set
        pathToDebugFolder = "../debug";
    }

    boost::filesystem::path setup_dir(pathToDebugFolder);
    return setup_dir;
}

void serializeProvingKeyToFile(libsnark::r1cs_ppzksnark_proving_key<ppT> pk, boost::filesystem::path pk_path)
{
    writeToFile(pk_path, pk);
}

r1cs_ppzksnark_proving_key<ppT> deserializeProvingKeyFromFile(boost::filesystem::path pk_path)
{
    return loadFromFile<libsnark::r1cs_ppzksnark_proving_key<ppT>>(pk_path);
}

void serializeVerificationKeyToFile(libsnark::r1cs_ppzksnark_verification_key<ppT> vk, boost::filesystem::path vk_path)
{
    writeToFile(vk_path, vk);
}

libsnark::r1cs_ppzksnark_verification_key<ppT> deserializeVerificationKeyFromFile(boost::filesystem::path vk_path)
{
    return loadFromFile<r1cs_ppzksnark_verification_key<ppT>>(vk_path);
}

void exportVerificationKey(libsnark::r1cs_ppzksnark_keypair<ppT> keypair)
{
    unsigned icLength = keypair.vk.encoded_IC_query.rest.indices.size() + 1;

    std::cout << "\tVerification key in Solidity compliant format:{" << std::endl;
    std::cout << "\t\tvk.A = Pairing.G2Point(" << outputPointG2AffineAsHex(keypair.vk.alphaA_g2) << ");" << std::endl;
    std::cout << "\t\tvk.B = Pairing.G1Point(" << outputPointG1AffineAsHex(keypair.vk.alphaB_g1) << ");" << std::endl;
    std::cout << "\t\tvk.C = Pairing.G2Point(" << outputPointG2AffineAsHex(keypair.vk.alphaC_g2) << ");" << std::endl;
    std::cout << "\t\tvk.gamma = Pairing.G2Point(" << outputPointG2AffineAsHex(keypair.vk.gamma_g2) << ");" << std::endl;
    std::cout << "\t\tvk.gammaBeta1 = Pairing.G1Point(" << outputPointG1AffineAsHex(keypair.vk.gamma_beta_g1) << ");" << std::endl;
    std::cout << "\t\tvk.gammaBeta2 = Pairing.G2Point(" << outputPointG2AffineAsHex(keypair.vk.gamma_beta_g2) << ");" << std::endl;
    std::cout << "\t\tvk.Z = Pairing.G2Point(" << outputPointG2AffineAsHex(keypair.vk.rC_Z_g2) << ");" << std::endl;
    std::cout << "\t\tvk.IC = new Pairing.G1Point[](" << icLength << ");" << std::endl;
    std::cout << "\t\tvk.IC[0] = Pairing.G1Point(" << outputPointG1AffineAsHex(keypair.vk.encoded_IC_query.first) << ");" << std::endl;
    for (size_t i = 1; i < icLength; ++i)
    {
        auto vkICi = outputPointG1AffineAsHex(keypair.vk.encoded_IC_query.rest.values[i - 1]);
        std::cout << "\t\tvk.IC[" << i << "] = Pairing.G1Point(" << vkICi << ");" << std::endl;
    }

    std::cout << "\t\t}" << std::endl;
}

void display_proof(libsnark::r1cs_ppzksnark_proof<ppT> proof)
{
    std::cout << "Proof:"<< std::endl;
    std::cout << "proof.A = Pairing.G1Point(" << outputPointG1AffineAsHex(proof.g_A.g)<< ");" << std::endl;
    std::cout << "proof.A_p = Pairing.G1Point(" << outputPointG1AffineAsHex(proof.g_A.h)<< ");" << std::endl;
    std::cout << "proof.B = Pairing.G2Point(" << outputPointG2AffineAsHex(proof.g_B.g)<< ");" << std::endl;
    std::cout << "proof.B_p = Pairing.G1Point(" << outputPointG1AffineAsHex(proof.g_B.h)<<");" << std::endl;
    std::cout << "proof.C = Pairing.G1Point(" << outputPointG1AffineAsHex(proof.g_C.g)<< ");" << std::endl;
    std::cout << "proof.C_p = Pairing.G1Point(" << outputPointG1AffineAsHex(proof.g_C.h)<<");" << std::endl;
    std::cout << "proof.H = Pairing.G1Point(" << outputPointG1AffineAsHex(proof.g_H)<<");"<< std::endl;
    std::cout << "proof.K = Pairing.G1Point(" << outputPointG1AffineAsHex(proof.g_K)<<");"<< std::endl;
}

void verificationKey_to_json(libsnark::r1cs_ppzksnark_keypair<ppT> keypair, boost::filesystem::path path)
{
    if path.empty()
    {
        boost::filesystem::path tmp_path = getPathToSetupDir();
        boost::filesystem::path vkey_json("vk.json");
        path = tmp_path / vkey_json;
    }
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

    for (size_t i = 1; i < icLength; ++i)
    {
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

void proof_to_json(libsnark::r1cs_ppzksnark_proof<ppT> proof, boost::filesystem::path path) {
	if path.empty()
    {
		boost::filesystem::path tmp_path = getPathToDebugDir();
		boost::filesystem::path proof_json("proof.json");
		path = tmp_path / proof_json;
	}
    // Convert the boost path into char*
    const char* str_path = path.string().c_str();

    std::stringstream ss;
    std::ofstream fh;
    fh.open(str_path, std::ios::binary);

    ss << "{\n";
    ss << " \"a\" :[" << outputPointG1AffineAsHex(proof.g_A.g) << "],\n";
    ss << " \"a_p\"  :[" << outputPointG1AffineAsHex(proof.g_A.h)<< "],\n";
    ss << " \"b\"  :[" << outputPointG2AffineAsHex(proof.g_B.g)<< "],\n";
    ss << " \"b_p\" :[" << outputPointG1AffineAsHex(proof.g_B.h)<< "],\n";
    ss << " \"c\" :[" << outputPointG1AffineAsHex(proof.g_C.g)<< "],\n";
    ss << " \"c_p\" :[" << outputPointG1AffineAsHex(proof.g_C.h)<< "],\n";
    ss << " \"h\" :[" << outputPointG1AffineAsHex(proof.g_H)<< "],\n";
    ss << " \"k\" :[" << outputPointG1AffineAsHex(proof.g_K)<< "]\n";
    ss << "}";

    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();
}

void write_setup(libsnark::r1cs_ppzksnark_keypair<ppT> keypair, boost::filesystem::path setup_dir)
{
	if path_prefix.empty()
    {
		boost::filesystem::path setup_dir = getPathToSetupDir();
	}

	boost::filesystem::path verif_key_json("vk.json");
	boost::filesystem::path verif_key_raw("vk.raw");
	boost::filesystem::path prov_key_raw("pk.raw");

	boost::filesystem::path path_verif_key_json = setup_dir / verif_key_json;
	boost::filesystem::path path_verif_key_raw = setup_dir / verif_key_raw;
	boost::filesystem::path path_prov_key_raw = setup_dir / prov_key_raw;

	verificationKey_to_json(keypair, path_verif_key_json);
	serializeProvingKeyToFile(keypair.pk, path_prov_key_raw);
	serializeVerificationKeyToFile(keypair.vk, path_verif_key_raw);
}


bool replace(std::string& str, const std::string& from, const std::string& to)
{
    size_t start_pos = str.find(from);
    if(start_pos == std::string::npos)
    {
        return false;
    }

    str.replace(start_pos, from.length(), to);
    return true;
}
