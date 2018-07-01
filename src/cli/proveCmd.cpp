#include "proveCmd.hpp"
#include <prover/prover.hpp>
#include <prover/computation.hpp>
#include <sha256/sha256_ethereum.hpp>

#define MAX_LENGTH_HEX 64

void printUsageProveCmd() {
    std::cerr << "Invalid number of arguments" << std::endl;
    std::cerr << "Usage: " << std::endl;
    std::cerr << "\t" << "sneth prove [tree_depth] [commitment_address] [secret] [nullifier] [commitment] [root] [merkle path (from top to bottom)...]" << std::endl;
}

int proveCommand(int argc, char* argv[]) {
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
    int error = checkNbArgs(argc - 2, args);
    if (error) {
        std::cerr << "[ERROR] Invalid number of arguments to generate the proof" << std::endl;
        printUsageProveCmd();
        return error;
    }

    // Convert arguments in a format that fits with the processing done in the backend
    int tree_depth = atoi(args[0]);
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

    libff::alt_bn128_pp::init_public_params();
    typedef libff::Fr<libff::alt_bn128_pp> FieldT;
    Miximus<FieldT, sha256_ethereum> prover;

    std::cout << "[DEBUG] Generating the proof" << std::endl;
    bool valid_proof = prover.prove(merkle_path, secret, nullifier, commitment, node_root, address_bits, size_t(address), size_t(tree_depth));
    if (!valid_proof) {
        std::cerr << "[ERROR] Invalid proof" << std::endl;
        return 1;
    }

    return 0;
}

int checkNbArgs(int nbArgs, char* args[]) {
    int tree_depth = atoi(args[0]); // See the expected ordering of the arguments in the printUsageProveCmd() function

    // By knowing the tree_depth, we can now compute the length of the 
    // merkle path and then know the expected number of arguments
    int nbArgsExpected = 1+1+1+1+1+1+tree_depth; // See nb of args in output of printUsageProveCmd()

    if (nbArgs != nbArgsExpected) {
        return 1;
    }

    return 0;
}

libff::bit_vector addressBitsFromAddress(int address, int tree_depth, int *error) {
    std::vector<bool> binary = convertIntToBinary(address);
    std::vector<bool> result(tree_depth, 0);
    
    if(binary.size() > tree_depth) {
        *error = 1; // We have an address that goes beyond the limit of the tree
        return libff::bit_vector(result);
    }

    // We need to "front pad" the bi conversion we obtained to have an address encoded by a binary
    // string of the length of the tree_depth
    if(binary.size() < tree_depth) {
        for (int i = 0; i < binary.size(); ++i) {
            result[(tree_depth - binary.size()) + i] = binary[i];
        }
        // We return the "front padded" vector
        return libff::bit_vector(result);
    }

    return libff::bit_vector(binary);
}

std::vector<bool> convertIntToBinary(int x) {
    std::vector<bool> ret;
    while(x) {
        if (x&1)
            ret.push_back(1);
        else
            ret.push_back(0);
        x>>=1;
    }
    reverse(ret.begin(),ret.end());
    return ret;
}

libff::bit_vector hexadecimalToBinaryVector(char* str, int* error) {
    std::string hex_str(str);
    std::vector<bool> result;
    std::vector<bool> tmp;
    std::vector<bool> zero_vector(256, 0);

    const std::vector<bool> vect0 = {0, 0, 0, 0};
    const std::vector<bool> vect1 = {0, 0, 0, 1};
    const std::vector<bool> vect2 = {0, 0, 1, 0};
    const std::vector<bool> vect3 = {0, 0, 1, 1};
    const std::vector<bool> vect4 = {0, 1, 0, 0};
    const std::vector<bool> vect5 = {0, 1, 0, 1};
    const std::vector<bool> vect6 = {0, 1, 1, 0};
    const std::vector<bool> vect7 = {0, 1, 1, 1};
    const std::vector<bool> vect8 = {1, 0, 0, 0};
    const std::vector<bool> vect9 = {1, 0, 0, 1};
    const std::vector<bool> vectA = {1, 0, 1, 0};
    const std::vector<bool> vectB = {1, 0, 1, 1};
    const std::vector<bool> vectC = {1, 1, 0, 0};
    const std::vector<bool> vectD = {1, 1, 0, 1};
    const std::vector<bool> vectE = {1, 1, 1, 0};
    const std::vector<bool> vectF = {1, 1, 1, 1};

    if(hex_str.length() != MAX_LENGTH_HEX) {
        *error = 1;
        return zero_vector; // Wrong size for the hexadecimal value (we want hexadecimal inputs of length 64)
    }

    for(std::string::iterator it = hex_str.begin(); it != hex_str.end(); ++it) {
        switch(*it) {
            case '0': tmp = vect0; break;
            case '1': tmp = vect1; break;
            case '2': tmp = vect2; break;
            case '3': tmp = vect3; break;
            case '4': tmp = vect4; break;
            case '5': tmp = vect5; break;
            case '6': tmp = vect6; break;
            case '7': tmp = vect7; break;
            case '8': tmp = vect8; break;
            case '9': tmp = vect9; break;
            case 'A': tmp = vectA; break;
            case 'a': tmp = vectA; break;
            case 'B': tmp = vectB; break;
            case 'b': tmp = vectB; break;
            case 'C': tmp = vectC; break;
            case 'c': tmp = vectC; break;
            case 'D': tmp = vectD; break;
            case 'd': tmp = vectD; break;
            case 'E': tmp = vectE; break;
            case 'e': tmp = vectE; break;
            case 'F': tmp = vectF; break;
            case 'f': tmp = vectF; break;
            default: *error = 1; return zero_vector;
        }
        result.insert(std::end(result), std::begin(tmp), std::end(tmp));
    }
    
    return libff::bit_vector(result);
}
