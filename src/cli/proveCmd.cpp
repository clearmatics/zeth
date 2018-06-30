#include "proveCmd.hpp"

void printUsageProveCmd() {
    std::cerr << "Invalid number of arguments" << std::endl;
    std::cerr << "Usage: " << std::endl;
    std::cerr << "\t" << "sneth prove [nodes of merkle path] [secret]" << std::endl;
}

void proveCommand(/*Miximus<FieldT, sha256_ethereum> prover, char* argv[]*/) {
    // 1. Check we have the valid number of arguments for the proof generation
    // 2. Verify the types of the args and the validity of the user data
    // 3. Format the inputs to use it with the prover (put binary strings in libff::bit_vectors and so on)
    // 4. Call the prover.prove function
    std::cout << "In the proveCommand function" << std::endl;
}
