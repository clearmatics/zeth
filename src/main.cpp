#include <iostream>

#include <libsnark_helpers/libsnark_helpers.hpp>
#include <prover/prover.hpp>
#include <prover/computation.hpp>
#include <sha256/sha256_ethereum.hpp>

enum command_code {
    SETUP,
    PROVE,
    UNKNOWN
};

void printUsage(std::string program);
command_code getCommandCode(std::string command);
void setupCommand(Miximus<FieldT, sha256_ethereum> prover);
void proveCommand();
void printUsageSetupCmd();
void printUsageProveCmd();

int main(int argc, char* argv[]) {
    // The first argument is the executable itself, and the second is the command
    // The executable itself does nothing, we need to specify a command
    std::string program(argv[0]);
    if (argc < 2) {
        printUsage(program);
        return 1;
    }

    // Two commands supported
    // One to compute the trusted setup, the other one to compute proofs
    std::string command(argv[1]);
    if (command != "setup" && command != "prove") {
        std::cerr << "Unknown command" << std::endl;
        printUsage(program);
        return 1;
    }
    
    // See: https://github.com/scipr-lab/libff/blob/master/libff/algebra/curves/alt_bn128/alt_bn128_init.cpp
    libff::alt_bn128_pp::init_public_params();
    typedef libff::Fr<libff::alt_bn128_pp> FieldT;

    // Instantiate the prover
    Miximus<FieldT, sha256_ethereum> prover;

    switch (getCommandCode(command)) {
        case SETUP: setupCommand(prover);
                      break;
        case PROVE: proveCommand();
                      break;
        default: std::cerr << "Unknown command" << std::endl;
                 printUsage(program);
                 return 1;
    }

    return 0;

    //// Values given by the user
    //libff::bit_vector leaf = node16;
    //
    //libff::bit_vector address_bits;
    //address_bits = {0,0,0,0};
    //size_t address = 0;

    //std::vector<merkle_authentication_node> merkle_path;
    //merkle_path = {node3,node5,node9,node17};

    //const size_t tree_depth = 4;

    //bool valid_proof = prover.prove(merkle_path, secret, nullifier, leaf, node_root, address_bits, address, tree_depth);

    //if (!valid_proof) {
    //    std::cout << "Invalid proof" << std::endl;
    //    return 1;
    //}

    //std::cout << "Proof generated successfully" << std::endl;
}


void printUsage(std::string program) {
    std::cerr << std::endl;
    std::cerr << "Usage: " << std::endl;
    std::cerr << "\t" << program << " command [arguments]" << std::endl;
    std::cerr << "The commands are:" << std::endl;
    std::cerr << "\t setup \t Run the trusted setup (generate proving and verifying keys)" << std::endl;
    std::cerr << "\t prove \t Generate a proof using the primary input (public), the auxiliary input (private), and the proving key" << std::endl;
}

command_code getCommandCode(std::string command) {
    if (command == "setup") return SETUP;
    if (command == "prove") return PROVE;
    return UNKNOWN;
}

void setupCommand(Miximus<FieldT, sha256_ethereum> prover) {
    std::cout << "Running the trusted setup..." << std::endl;
    prover.generate_trusted_setup();
    std::cout << "Trusted setup successfully generated" << std::endl;
}

void printUsageSetupCmd() {
    std::cerr << "Invalid number of arguments" << std::endl;
    std::cerr << "Usage: " << std::endl;
    std::cerr << "\t" << "sneth setup [nodes of merkle path] [secret]" << std::endl;
}

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
