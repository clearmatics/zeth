template<typename T>
void writeToFile(std::string path, T& obj) {
    std::stringstream ss;
    ss << obj;
    std::ofstream fh;

    fh.open(path, std::ios::binary);
    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();
}

template<typename T>
T loadFromFile(std::string path) {
    std::stringstream ss;
    std::ifstream fh(path, std::ios::binary);

    assert(fh.is_open());

    ss << fh.rdbuf();
    fh.close();
    ss.rdbuf()->pubseekpos(0, std::ios_base::in);

    T obj;
    ss >> obj;

    return obj;
}

template<typename FieldT>
void constraint_to_json(libsnark::linear_combination<FieldT> constraints, std::string path) {
    std::stringstream ss;
    std::ofstream fh;
    fh.open(path, std::ios::binary);

    ss << "{";
    uint count = 0;
    for (const libsnark::linear_term<FieldT>& lt : constraints.terms) {
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

template <typename FieldT>
void array_to_json(libsnark::protoboard<FieldT> pb, uint input_variables, std::string path) {
    std::stringstream ss;
    std::ofstream fh;
    fh.open(path, std::ios::binary);

    libsnark::r1cs_variable_assignment<FieldT> values = pb.full_variable_assignment();
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

template<typename FieldT>
void r1cs_to_json(libsnark::protoboard<FieldT> pb, uint input_variables, std::string path) {
    // output inputs, right now need to compile with debug flag so that the `variable_annotations`
    // exists. Having trouble setting that up so will leave for now.
    libsnark::r1cs_constraint_system<FieldT> constraints = pb.get_constraint_system();
    std::stringstream ss;
    std::ofstream fh;
    fh.open(path, std::ios::binary);

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

template<typename FieldT>
void proof_to_json(libsnark::r1cs_ppzksnark_proof<libff::alt_bn128_pp> proof, libsnark::r1cs_primary_input<FieldT> input) {
    std::cout << "proof.A = Pairing.G1Point(" << outputPointG1AffineAsHex(proof.g_A.g)<< ");" << std::endl;
    std::cout << "proof.A_p = Pairing.G1Point(" << outputPointG1AffineAsHex(proof.g_A.h)<< ");" << std::endl;
    std::cout << "proof.B = Pairing.G2Point(" << outputPointG2AffineAsHex(proof.g_B.g)<< ");" << std::endl;
    std::cout << "proof.B_p = Pairing.G1Point(" << outputPointG1AffineAsHex(proof.g_B.h)<<");" << std::endl;
    std::cout << "proof.C = Pairing.G1Point(" << outputPointG1AffineAsHex(proof.g_C.g)<< ");" << std::endl;
    std::cout << "proof.C_p = Pairing.G1Point(" << outputPointG1AffineAsHex(proof.g_C.h)<<");" << std::endl;
    std::cout << "proof.H = Pairing.G1Point(" << outputPointG1AffineAsHex(proof.g_H)<<");"<< std::endl;
    std::cout << "proof.K = Pairing.G1Point(" << outputPointG1AffineAsHex(proof.g_K)<<");"<< std::endl; 

    std::string path = "proof.json";
    std::stringstream ss;
    std::ofstream fh;
    fh.open(path, std::ios::binary);
    
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

template<typename FieldT>
void exportInput(libsnark::r1cs_primary_input<FieldT> input) {
    std::cout << "\ninput = [";
    for (size_t i = 1; i < input.size(); ++i) {
        std::cout << input[i] << " , ";
    }
    std::cout << "];\n";
}
