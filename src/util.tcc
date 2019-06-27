#ifndef __ZETH_UTIL_TCC__
#define __ZETH_UTIL_TCC__

#include<iostream>
#include<algorithm>
#include<vector>
#include<stdexcept>

#include "zeth.h"

namespace libzeth {

// Takes a binary string and swaps the bit endianness
template<typename T>
T swap_bit_endianness(T v) {
    int len = v.size();
    if (len == 0) {
        throw std::length_error("Invalid bit length for the given boolean vector (should be > 0)");
    }

    for(size_t i = 0; i < len/2; i++) {
        std::swap(v[i], v[(len - 1)-i]);
    }

    return v;
}

std::vector<bool> address_bits_from_address(int address, int tree_depth) {
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


/*
 * string_to_field(std::string input) converts a string ob bytes of size <=32 to a FieldT element.
 */
template<typename FieldT>
FieldT string_to_field(std::string input){

    //TODO: add sanity check on the type of string we pass
    //Sanity checks
    if (input.length() == 0 || input.length() > 64) {
        throw std::length_error("Invalid byte string length for the given field string");
    }

    // Copy the string into a char array
    char char_array[input.length()+1];
    strcpy(char_array, input.c_str());

    //Construct gmp integer from the string
    mpz_t n;
    mpz_init(n);

    int flag = mpz_set_str(n, char_array, 16);
    assert(flag == 0 && "mpz initialization failed.");

    //Construct libff::bigint from gmp integer
    libff::bigint<4> n_big_int = libff::bigint<4>(n);//TODO check 4

    //Construct field element from a bigint
    FieldT element = FieldT(n_big_int);
    return element;
  }

// Dump a vector into an array
template<size_t Size>
std::array<bool, Size> dump_vector_in_array(std::vector<bool> vect) {
    std::array<bool, Size> array;
    if (vect.size() != Size) {
        throw std::length_error("Invalid bit length for the given boolean vector (should be equal to the size of the vector)");
    }

    std::copy(vect.begin(), vect.end(), array.begin());
    return array;
};

// Dump an array into a vector
template<size_t Size>
std::vector<bool> dump_array_in_vector(std::array<bool, Size> arr) {
    std::vector<bool> vect(Size);
    std::copy(arr.begin(), arr.end(), vect.begin());
    return vect;
}


std::vector<bool> get_vector_from_bitsAddr(bitsAddr arr) {
    return dump_array_in_vector<ZETH_MERKLE_TREE_DEPTH>(arr);
}

bitsAddr get_bitsAddr_from_vector(std::vector<bool> vect) {
    return dump_vector_in_array<ZETH_MERKLE_TREE_DEPTH>(vect);
}

} // libzeth

#endif // __ZETH_UTIL_TCC__
