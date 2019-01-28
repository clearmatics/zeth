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

bits256 get_bits256_from_vector(std::vector<bool> vect) {
    return dump_vector_in_array<256>(vect);
};

bits64 get_bits64_from_vector(std::vector<bool> vect) {
    return dump_vector_in_array<64>(vect);
};

// Dump an array into a vector
template<size_t Size>
std::vector<bool> dump_array_in_vector(std::array<bool, Size> arr) {
    std::vector<bool> vect(Size);
    std::copy(arr.begin(), arr.end(), vect.begin());
    return vect;
}

std::vector<bool> get_vector_from_bits256(bits256 arr) {
    return dump_array_in_vector<256>(arr);
};

std::vector<bool> get_vector_from_bits64(bits64 arr) {
    return dump_array_in_vector<64>(arr);
};

#endif // __ZETH_BITS256_TCC__