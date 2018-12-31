#ifndef __ZETH_LIBSNARK_HELPERS_TCC__
#define __ZETH_LIBSNARK_HELPERS_TCC__

template<typename T>
void writeToFile(boost::filesystem::path path, T& obj) {
    // Convert the boost path into char*
    const char* str_path = path.string().c_str();

    std::stringstream ss;
    ss << obj;
    std::ofstream fh;

    fh.open(str_path, std::ios::binary);
    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();
}

template<typename T>
T loadFromFile(boost::filesystem::path path) {
    // Convert the boost path into char*
    const char* str_path = path.string().c_str();

    std::stringstream ss;
    std::ifstream fh(str_path, std::ios::binary);

    assert(fh.is_open());

    ss << fh.rdbuf();
    fh.close();
    ss.rdbuf()->pubseekpos(0, std::ios_base::in);

    T obj;
    ss >> obj;

    return obj;
}

template<typename ppT>
void constraint_to_json(libsnark::linear_combination<libff::Fr<ppT> > constraints, boost::filesystem::path path)
{
	//if (path.empty())
    //{
		boost::filesystem::path tmp_path = getPathToDebugDir();
		boost::filesystem::path constraints_json("constraints.json");
		path = tmp_path / constraints_json;
	//}
    // Convert the boost path into char*
    const char* str_path = path.string().c_str();

    std::stringstream ss;
    std::ofstream fh;
    fh.open(str_path, std::ios::binary);

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
    ss.rdbuf()->pubseekpos(0, std::ios_base::out);

    fh << ss.rdbuf();
    fh.flush();
    fh.close();
}

template <typename ppT>
void array_to_json(libsnark::protoboard<libff::Fr<ppT> > pb, uint input_variables, boost::filesystem::path path) {
	if (path.empty()) {
		boost::filesystem::path tmp_path = getPathToDebugDir();
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
		boost::filesystem::path tmp_path = getPathToDebugDir();
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
        constraint_to_json(constraints.constraints[c].a, ss);
        ss << ",";// << "\"B\"=";
        constraint_to_json(constraints.constraints[c].b, ss);
        ss << ",";// << "\"A\"=";;
        constraint_to_json(constraints.constraints[c].c, ss);
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
		boost::filesystem::path tmp_path = getPathToDebugDir();
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
		boost::filesystem::path tmp_path = getPathToDebugDir();
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
