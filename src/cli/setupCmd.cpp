#include "setupCmd.hpp"

int setupCommand(Miximus<FieldT, sha256_ethereum> prover) {
    std::cout << "Running the trusted setup..." << std::endl;
    prover.generate_trusted_setup();
    std::cout << "Trusted setup successfully generated" << std::endl;
    return 0;
}

void printUsageSetupCmd() {
    std::cerr << "Invalid number of arguments" << std::endl;
    std::cerr << "Usage: " << std::endl;
    std::cerr << "\t" << "zeth setup" << std::endl;
    // TODO: implement optional path to folder where to store the result of the trusted setup
    // Default/hardcoded value is ../zksnark_element for now
}
