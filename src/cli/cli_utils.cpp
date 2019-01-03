#include "cli_utils.hpp"

#define MAX_LENGTH_HEX 64

int checkNbArgs(int nbArgs, int expectedNbArgs, char* args[]) {
    if (nbArgs != expectedNbArgs) {
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
    std::reverse(ret.begin(),ret.end());
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
