template<typename FieldT, typename HashT>
int proveCommand(Miximus<FieldT, HashT> prover, int argc, char* argv[]) {
    // The minus 2 comes from the fact that argv[0] is the executable itself,
    // and argv[1] is the command, so now we check the number of args for the given command
    if (argc - 2 <= 0) {
        std::cerr << "[ERROR] Invalid number of arguments to generate the proof" << std::endl;
        printUsageProveCmd();
        return 1;
    }

    char* args[argc - 2];
    for (int i = 0; i < argc - 2; i++) {
        // We extract the arguments of the command from argv
        // to get rid of the executable and the command
        args[i] = argv[2+i];
    }

    // argc - 2 being the number of args for the command prove
    // We check the number of args for this given command
    int tree_depth = atoi(args[0]); // See the expected ordering of the arguments in the printUsageProveCmd() function
    int expectedNbArgs = 1+1+1+1+1+1+tree_depth; // See nb of args in output of printUsageProveCmd()
    int error = checkNbArgs(argc - 2, expectedNbArgs, args);
    if (error) {
        std::cerr << "[ERROR] Invalid number of arguments to generate the proof" << std::endl;
        printUsageProveCmd();
        return error;
    }

    // Convert arguments in a format that fits with the processing done in the backend
    int address = atoi(args[1]);
    libff::bit_vector secret = hexadecimalToBinaryVector(args[2], &error);
    if (error) {
        std::cerr << "[ERROR] Error while computing bit vector from secret hexadecimal" << std::endl;
        return error;
    }

    libff::bit_vector nullifier = hexadecimalToBinaryVector(args[3], &error);
    if (error) {
        std::cerr << "[ERROR] Error while computing bit vector from nullifier hexadecimal" << std::endl;
        return error;
    }

    libff::bit_vector commitment = hexadecimalToBinaryVector(args[4], &error);
    if (error) {
        std::cerr << "[ERROR] Error while computing bit vector from commitment hexadecimal" << std::endl;
        return error;
    }

    libff::bit_vector node_root = hexadecimalToBinaryVector(args[5], &error);
    if (error) {
        std::cerr << "[ERROR] Error while computing bit vector from root node hexadecimal" << std::endl;
        return error;
    }

    std::vector<merkle_authentication_node> merkle_path;
    for (int i = 0; i < tree_depth; i++) {
        merkle_authentication_node merkle_node = merkle_authentication_node(hexadecimalToBinaryVector(args[6 + i], &error));
        if (error) {
            std::cerr << "[ERROR] Error while computing bit vector from merkle node hexadecimal" << std::endl;
            return error;
        }
        merkle_path.push_back(merkle_node);
        // Make sure we puch the merkle nodes in the good order: merkle_path = {node3,node5,node9,node17};
    }

    // Compute address_bits from address
    libff::bit_vector address_bits = addressBitsFromAddress(address, tree_depth, &error);
    if (error) {
        std::cerr << "[ERROR] Error while computing address_bits from address" << std::endl;
        return error;
    }

    // Useless, should be done only once
    //libff::alt_bn128_pp::init_public_params();
    //typedef libff::Fr<libff::alt_bn128_pp> FieldT;
    //Miximus<FieldT, sha256_ethereum> prover; // Given as argument

    std::cout << "[DEBUG] Generating the proof" << std::endl;
    bool valid_proof = prover.prove(merkle_path, secret, nullifier, commitment, node_root, address_bits, size_t(address), size_t(tree_depth));
    if (!valid_proof) {
        std::cerr << "[ERROR] Invalid proof" << std::endl;
        return 1;
    }

    return 0;
}
