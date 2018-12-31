template<typename ppT, typename HashT>
int proveCommand(Miximus<ppT, HashT> prover, int argc, char* argv[]) {
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

    // zeth prove [tree_depth] [commitment_address] [secret] [nullifier] [commitment-digest] [root-digest] [merkle path (from top to bottom)]
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

    std::cout << "[DEBUG] Reading and loading the proof from default file location" << std::endl;
    boost::filesystem::path setup_dir = getPathToSetupDir();
    boost::filesystem::path prov_key_raw("pk.raw");
    boost::filesystem::path path_prov_key_raw = setup_dir / prov_key_raw;
    libsnark::r1cs_ppzksnark_proving_key<ppT> pk;
    // TODO: Refactor this try/catch block by handling errors correctly in backend functions (adding a int& error arg to critical functions)
    try {
        pk = deserializeProvingKeyFromFile(path_prov_key_raw);
    } catch (const std::exception& e) {
        std::cerr << "[FATAL] Error while loading the proving key: Verify that your environment is correctly configured "
            << "(" << e.what() << ")" << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "[FATAL] Unhandled error" << std::endl;
        return 1;
    }

    std::cout << "[DEBUG] Generating the proof" << std::endl;
    extended_proof<ppT> proof = prover.prove(merkle_path, secret, nullifier, commitment, node_root, address_bits, size_t(address), size_t(tree_depth), pk);

    std::cout << "[DEBUG] Displaying the extended proof" << std::endl;
    proof.dump_proof();
    proof.dump_primary_inputs();

    return 0;
}
