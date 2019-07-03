#include<iostream>
#include<algorithm>
#include<vector>
#include<stdexcept>

#include "zeth.h"
#include "util.hpp"

namespace libzeth {

// Takes a binary string and swaps the bit endianness
template<typename T>
T swap_bit_endianness(T v) {
    size_t len = v.size();
    if (len == 0) {
        throw std::length_error("Invalid bit length for the given boolean vector (should be > 0)");
    }

    for(size_t i = 0; i < len/2; i++) {
        std::swap(v[i], v[(len - 1)-i]);
    }

    return v;
}

// Takes an hexadecimal string and converts it into a binary vector
std::vector<bool> hexadecimal_str_to_binary_vector(std::string hex_str) {
    std::vector<bool> result;
    std::vector<bool> tmp;
    std::vector<bool> zero_vector(hex_str.length() * 4, 0); // Each hex character is encoded on 4bits

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
            default: throw std::invalid_argument("Invalid hexadecimnal character");
        }
        result.insert(std::end(result), std::begin(tmp), std::end(tmp));
    }

    return result;
}

// Takes an hexadecimal digest and converts it into a binary vector
std::vector<bool> hexadecimal_digest_to_binary_vector(std::string hex_str) {
    if(hex_str.length() != ZETH_DIGEST_HEX_SIZE) {
        throw std::length_error("Invalid string length for the given hexadecimal digest (should be ZETH_DIGEST_HEX_SIZE)");
    }


    return hexadecimal_str_to_binary_vector(hex_str);
}

bits256 hexadecimal_digest_to_bits256(std::string str) {
    return get_bits256_from_vector(hexadecimal_digest_to_binary_vector(str));
}

bits64 hexadecimal_value_to_bits64(std::string str) {
    return get_bits64_from_vector(hexadecimal_str_to_binary_vector(str));
}

std::vector<bool> address_bits_from_address(int address, size_t tree_depth) {
    std::vector<bool> binary = convert_int_to_binary(address);
    std::vector<bool> result(tree_depth, 0);

    if(binary.size() > tree_depth) {
        // Address encoded on more bits that the address space allows
        throw std::invalid_argument("Address overflow");
    }

    // We need to "back pad" the binary conversion we obtained to have an address encoded
    // by a binary string of the length of the tree_depth
    if(binary.size() < tree_depth) {
        for (size_t i = 0; i < binary.size(); i++) {
            result[i] = binary[i];
        }
        // We return the "back padded" vector
        return result;
    }

    return binary;
}

// As we push_back in the vector, this function returns the little endian
// binary encoding of the integer x
std::vector<bool> convert_int_to_binary(int x) {
    std::vector<bool> ret;
    while(x) {
        if (x&1)
            ret.push_back(1);
        else
            ret.push_back(0);
        x>>=1;
    }
    return ret;
}

} // libzeth
