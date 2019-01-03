#ifndef __ZETH_LIBSNARK_HELPERS_TCC__
#define __ZETH_LIBSNARK_HELPERS_TCC__

// SerializableT represents any type that overloads the operator<< and operator>> of ostream and istream
// Note: Both r1cs_ppzksnark_proving_key and r1cs_ppzksnark_verifying_key implement
// these overloading, so both of them can easily be writen and loaded from files
template<typename serializableT>
void writeToFile(boost::filesystem::path path, serializableT& obj) {
    // Convert the boost path into char*
    const char* str_path = path.string().c_str();

    std::stringstream ss;
    ss << obj;

    // ofstream: Stream class to write on files
    std::ofstream fh;

    fh.open(str_path, std::ios::binary); // We open our ofstream in binary mode
    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();
}

template<typename serializableT>
serializableT loadFromFile(boost::filesystem::path path) {
    // Convert the boost path into char*
    const char* str_path = path.string().c_str();

    std::stringstream ss;

    // ifstream: Stream class to read from files (opened in binary mode)
    std::ifstream fh(str_path, std::ios::binary);
    assert(fh.is_open());

    // Get a stream buffer from the ifstream and "dump" its content to the stringstream
    ss << fh.rdbuf();
    fh.close();

    // Set internal position pointer to absolute position 0
    ss.rdbuf()->pubseekpos(0, std::ios_base::in);

    serializableT obj;
    ss >> obj;

    return obj;
}

template<typename ppT>
void serializeProvingKeyToFile(libsnark::r1cs_ppzksnark_proving_key<ppT> pk, boost::filesystem::path pk_path)
{
    writeToFile<libsnark::r1cs_ppzksnark_proving_key<ppT> >(pk_path, pk);
}

template<typename ppT>
libsnark::r1cs_ppzksnark_proving_key<ppT> deserializeProvingKeyFromFile(boost::filesystem::path pk_path)
{
    return loadFromFile<libsnark::r1cs_ppzksnark_proving_key<ppT> >(pk_path);
}

template<typename ppT>
void serializeVerificationKeyToFile(libsnark::r1cs_ppzksnark_verification_key<ppT> vk, boost::filesystem::path vk_path)
{
    writeToFile<libsnark::r1cs_ppzksnark_verification_key<ppT> >(vk_path, vk);
}

template<typename ppT>
libsnark::r1cs_ppzksnark_verification_key<ppT> deserializeVerificationKeyFromFile(boost::filesystem::path vk_path)
{
    return loadFromFile<libsnark::r1cs_ppzksnark_verification_key<ppT> >(vk_path);
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
}

template<typename ppT>
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

template<typename ppT>
void verificationKey_to_json(libsnark::r1cs_ppzksnark_verification_key<ppT> vk, boost::filesystem::path path)
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
}

template<typename ppT>
void proof_to_json(libsnark::r1cs_ppzksnark_proof<ppT> proof, boost::filesystem::path path) {
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
}

template<typename ppT>
void write_setup(libsnark::r1cs_ppzksnark_keypair<ppT> keypair, boost::filesystem::path setup_dir)
{
	if (setup_dir.empty())
    {
        setup_dir = getPathToSetupDir();
	}

	boost::filesystem::path vk_json("vk.json");
	boost::filesystem::path vk_raw("vk.raw");
	boost::filesystem::path pk_raw("pk.raw");

	boost::filesystem::path path_vk_json = setup_dir / vk_json;
	boost::filesystem::path path_vk_raw = setup_dir / vk_raw;
	boost::filesystem::path path_pk_raw = setup_dir / pk_raw;

    libsnark::r1cs_ppzksnark_proving_key<ppT> proving_key = keypair.pk;
    libsnark::r1cs_ppzksnark_verification_key<ppT> verification_key = keypair.vk;

	verificationKey_to_json<ppT>(verification_key, path_vk_json);

	serializeVerificationKeyToFile<ppT>(verification_key, path_vk_raw);
	serializeProvingKeyToFile<ppT>(proving_key, path_pk_raw);
}

template<typename ppT>
void r1cs_constraints_to_json(libsnark::linear_combination<libff::Fr<ppT> > constraints, boost::filesystem::path path)
{
	if (path.empty())
    {
		boost::filesystem::path tmp_path = getPathToDebugDir(); // Used for a debug purpose
		boost::filesystem::path constraints_json("constraints.json");
		path = tmp_path / constraints_json;
	}
    // Convert the boost path into char*
    const char* str_path = path.string().c_str();

    std::stringstream ss;
    std::ofstream fh;
    fh.open(str_path, std::ios::binary);

    fill_json_constraints_in_ss(constraints, ss);

    ss.rdbuf()->pubseekpos(0, std::ios_base::out);

    fh << ss.rdbuf();
    fh.flush();
    fh.close();
}

template<typename ppT>
void fill_json_constraints_in_ss(libsnark::linear_combination<libff::Fr<ppT> > constraints, std::stringstream& ss)
{
    ss << "{";
    uint count = 0;
    for (const libsnark::linear_term<libff::Fr<ppT> >& lt : constraints.terms) {
        if (count != 0) {
            ss << ",";
        }

        if (lt.coeff != 0 && lt.coeff != 1) {
            ss << '"' << lt.index << '"' << ":" << "-1";
        } else {
            ss << '"' << lt.index << '"' << ":" << lt.coeff;
        }
        count++;
    }
    ss << "}";
}

template <typename ppT>
void array_to_json(libsnark::protoboard<libff::Fr<ppT> > pb, uint input_variables, boost::filesystem::path path) {
	if (path.empty())
    {
		boost::filesystem::path tmp_path = getPathToDebugDir(); // Used for a debug purpose
		boost::filesystem::path array_json("array.json");
		path = tmp_path / array_json;
	}
    // Convert the boost path into char*
    const char* str_path = path.string().c_str();

    std::stringstream ss;
    std::ofstream fh;
    fh.open(str_path, std::ios::binary);

    libsnark::r1cs_variable_assignment<libff::Fr<ppT> > values = pb.full_variable_assignment();
    ss << "\n{\"TestVariables\":[";

    for (size_t i = 0; i < values.size(); ++i) {
        ss << values[i].as_bigint();
        if (i <  values.size() - 1) { ss << ",";}
    }

    ss << "]}\n";
    ss.rdbuf()->pubseekpos(0, std::ios_base::out);

    fh << ss.rdbuf();
    fh.flush();
    fh.close();
}

template<typename ppT>
void r1cs_to_json(libsnark::protoboard<libff::Fr<ppT> > pb, uint input_variables, boost::filesystem::path path) {
	if (path.empty()) {
		boost::filesystem::path tmp_path = getPathToDebugDir(); // Used for a debug purpose
		boost::filesystem::path r1cs_json("r1cs.json");
		path = tmp_path / r1cs_json;
	}
    // Convert the boost path into char*
    const char* str_path = path.string().c_str();

    // output inputs, right now need to compile with debug flag so that the `variable_annotations`
    // exists. Having trouble setting that up so will leave for now.
    libsnark::r1cs_ppzksnark_constraint_system<ppT> constraints = pb.get_constraint_system();
    std::stringstream ss;
    std::ofstream fh;
    fh.open(str_path, std::ios::binary);

    ss << "\n{\"variables\":[";

    for (size_t i = 0; i < input_variables + 1; ++i) {
        ss << '"' << constraints.variable_annotations[i].c_str() << '"';
        if (i < input_variables ) {
            ss << ", ";
        }
    }
    ss << "],\n";
    ss << "\"constraints\":[";

    for (size_t c = 0; c < constraints.num_constraints(); ++c) {
        ss << "[";// << "\"A\"=";
        fill_json_constraints_in_ss<ppT>(constraints.constraints[c].a, ss);
        ss << ",";// << "\"B\"=";
        fill_json_constraints_in_ss<ppT>(constraints.constraints[c].b, ss);
        ss << ",";// << "\"A\"=";;
        fill_json_constraints_in_ss<ppT>(constraints.constraints[c].c, ss);
        if (c == constraints.num_constraints()-1 ) {
            ss << "]\n";
        } else {
            ss << "],\n";
        }
    }
    ss << "]}";

    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();
}

template<typename ppT>
void proof_and_input_to_json(libsnark::r1cs_ppzksnark_proof<ppT> proof, libsnark::r1cs_ppzksnark_primary_input<ppT> input, boost::filesystem::path path) {
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
}

template<typename ppT>
void primary_input_to_json(libsnark::r1cs_ppzksnark_primary_input<ppT> input, boost::filesystem::path path) {
	if (path.empty()) {
		boost::filesystem::path tmp_path = getPathToDebugDir(); // Used for a debug purpose
		boost::filesystem::path primary_input_json("primary_input.json");
		path = tmp_path / primary_input_json;
	}
    // Convert the boost path into char*
    const char* str_path = path.string().c_str();

    std::stringstream ss;
    std::ofstream fh;
    fh.open(str_path, std::ios::binary);

    ss << "{\n";
    ss << " \"inputs\" :" << "["; // 1 should always be the first variable passed
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
}

template<typename ppT>
void display_primary_input(libsnark::r1cs_ppzksnark_primary_input<ppT> input) {
    std::cout << "\ninput = [";
    for (size_t i = 1; i < input.size(); ++i) {
        std::cout << input[i] << " , ";
    }
    std::cout << "];\n";
}

#endif
