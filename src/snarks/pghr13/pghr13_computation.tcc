#ifndef __ZETH_PGHR13_COMPUTATION_TCC__
#define __ZETH_PGHR13_COMPUTATION_TCC__

namespace libzeth {

    // Generate the proof and returns a struct {proof, primary_input}
    template<typename ppT>
    libsnark::r1cs_ppzksnark_proof<ppT> gen_proof(libsnark::protoboard<libff::Fr<ppT> > pb, libsnark::r1cs_ppzksnark_proving_key<ppT> proving_key)
    {
        // See: https://github.com/scipr-lab/libsnark/blob/92a80f74727091fdc40e6021dc42e9f6b67d5176/libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp#L81
        // For the definition of r1cs_primary_input and r1cs_auxiliary_input
        libsnark::r1cs_primary_input<libff::Fr<ppT>> primary_input = pb.primary_input();
        libsnark::r1cs_auxiliary_input<libff::Fr<ppT>> auxiliary_input = pb.auxiliary_input();

        // Generate proof from public input, auxiliary input (private/secret data), and proving key
        proofT<ppT> proof = libsnark::r1cs_ppzksnark_prover(proving_key, primary_input, auxiliary_input);

        return proof;
    }

    // Run the trusted setup and returns a struct {proving_key, verifying_key}
    template<typename ppT>
    keyPairT<ppT> gen_trusted_setup(libsnark::protoboard<libff::Fr<ppT> > pb)
    {
        // Generate verification and proving key (Trusted setup) from the R1CS (defined in the ZoKrates/wraplibsnark.cpp file)
        // This function, basically reduces the R1CS into a QAP, and then encodes the QAP, along with a secret s and its
        // set of powers, plus the alpha, beta, gamma, and the rest of the entries, in order to form the CRS
        // (crs_f, shortcrs_f, as denoted in [GGPR12]) 
        
        //TODO: find another solution. Here it is difficult make overloading
        return libsnark::r1cs_ppzksnark_generator<ppT>(pb.get_constraint_system());
        }

    template<typename ppT>
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
    };

    template<typename ppT>
    void displayProof(libsnark::r1cs_ppzksnark_proof<ppT> proof)
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
    };

    template<typename ppT>
    void verificationKeyToJson(libsnark::r1cs_ppzksnark_verification_key<ppT> vk, boost::filesystem::path path)
    {
        if (path.empty())
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
        unsigned icLength = vk.encoded_IC_query.rest.indices.size() + 1;

        ss << "{\n";
        ss << " \"a\" :[" << outputPointG2AffineAsHex(vk.alphaA_g2) << "],\n";
        ss << " \"b\"  :[" << outputPointG1AffineAsHex(vk.alphaB_g1) << "],\n";
        ss << " \"c\" :[" << outputPointG2AffineAsHex(vk.alphaC_g2) << "],\n";
        ss << " \"g\" :[" << outputPointG2AffineAsHex(vk.gamma_g2)<< "],\n";
        ss << " \"gb1\" :[" << outputPointG1AffineAsHex(vk.gamma_beta_g1)<< "],\n";
        ss << " \"gb2\" :[" << outputPointG2AffineAsHex(vk.gamma_beta_g2)<< "],\n";
        ss << " \"z\" :[" << outputPointG2AffineAsHex(vk.rC_Z_g2)<< "],\n";

        ss <<  "\"IC\" :[[" << outputPointG1AffineAsHex(vk.encoded_IC_query.first) << "]";

        for (size_t i = 1; i < icLength; ++i)
        {
            auto vkICi = outputPointG1AffineAsHex(vk.encoded_IC_query.rest.values[i - 1]);
            ss << ",[" <<  vkICi << "]";
        }

        ss << "]";
        ss << "}";
        ss.rdbuf()->pubseekpos(0, std::ios_base::out);
        fh << ss.rdbuf();
        fh.flush();
        fh.close();
    };

    template<typename ppT>
    void proofToJson(libsnark::r1cs_ppzksnark_proof<ppT> proof, boost::filesystem::path path) {
        if (path.empty())
        {
            boost::filesystem::path tmp_path = getPathToDebugDir(); // Used for a debug purpose
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
    };

    template<typename ppT>
    void proofAndInputToJson(libsnark::r1cs_ppzksnark_proof<ppT> proof, libsnark::r1cs_ppzksnark_primary_input<ppT> input, boost::filesystem::path path) {
        if (path.empty()) {
            boost::filesystem::path tmp_path = getPathToDebugDir(); // Used for a debug purpose
            boost::filesystem::path proof_and_input_json("proof_and_input.json");
            path = tmp_path / proof_and_input_json;
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
        ss << " \"k\" :[" << outputPointG1AffineAsHex(proof.g_K)<< "],\n";
        ss << " \"input\" :" << "["; // 1 should always be the first variable passed

        for (size_t i = 0; i < input.size(); ++i) {
            ss << "\"0x" << HexStringFromLibsnarkBigint(input[i].as_bigint()) << "\"";
            if ( i < input.size() - 1 ) {
                ss<< ", ";
            }
        }

        ss << "]\n";
        ss << "}";
        ss.rdbuf()->pubseekpos(0, std::ios_base::out);
        fh << ss.rdbuf();
        fh.flush();
        fh.close();
    };

} // libzeth

#endif
