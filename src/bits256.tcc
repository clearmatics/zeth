#ifndef __ZETH_BITS256_TCC__
#define __ZETH_BITS256_TCC__

#include <array>
#include <vector>

#include "bits256.hpp"

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

bits384 get_bits384_from_vector(std::vector<bool> vect) {
    return dump_vector_in_array<384>(vect);
};

bits256 get_bits256_from_vector(std::vector<bool> vect) {
    return dump_vector_in_array<256>(vect);
};

bits64 get_bits64_from_vector(std::vector<bool> vect) {
    return dump_vector_in_array<64>(vect);
};

bitsAddr get_bitsAddr_from_vector(std::vector<bool> vect) {
    return dump_vector_in_array<ZETH_MERKLE_TREE_DEPTH>(vect);
};

// Dump an array into a vector
template<size_t Size>
std::vector<bool> dump_array_in_vector(std::array<bool, Size> arr) {
    std::vector<bool> vect(Size);
    std::copy(arr.begin(), arr.end(), vect.begin());
    return vect;
}

std::vector<bool> get_vector_from_bits384(bits384 arr) {
    return dump_array_in_vector<384>(arr);
};

std::vector<bool> get_vector_from_bits256(bits256 arr) {
    return dump_array_in_vector<256>(arr);
};

std::vector<bool> get_vector_from_bits64(bits64 arr) {
    return dump_array_in_vector<64>(arr);
};

std::vector<bool> get_vector_from_bitsAddr(bitsAddr arr) {
    return dump_array_in_vector<ZETH_MERKLE_TREE_DEPTH>(arr);
};

// Sum 2 binary strings
template<size_t BitLen>
std::array<bool, BitLen> binaryAddition(std::array<bool, BitLen> A, std::array<bool, BitLen> B) {
    std::array<bool, BitLen> sum;
    sum.fill(0);
    
    bool carry = 0;
    for(int i = BitLen - 1; i >= 0; i--){
        sum[i] = ((A[i] ^ B[i]) ^ carry); // c is carry
        carry = ((A[i] & B[i]) | (A[i] & carry)) | (B[i] & carry);
        std::cout << "Carry: " << carry << std::endl;
    }
    
    // If the last carry is 1, then we have an overflow
    if(carry) {
        throw std::overflow_error("Overflow: The sum of the binary addition cannot be encoded on <BitLen> bits");
    }
    
    return sum;
}

bits64 sum_bits64(bits64 a, bits64 b) {
    std::array<bool, 64> sum;

    try {
        sum = binaryAddition(a, b);
    } catch (const std::overflow_error& e) {
        // We return 0 encoded in binary if we overflow
        sum.fill(0);
    }
    
    return sum;
};


#endif // __ZETH_BITS256_TCC__