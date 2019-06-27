#ifndef __ZETH_UTIL_HPP__
#define __ZETH_UTIL_HPP__

#include <vector>
#include <string>
#include <cstdint>

namespace libzeth {

typedef std::array<bool, ZETH_MERKLE_TREE_DEPTH> bitsAddr;

template<typename T>
T swap_bit_endianness(T v);

std::vector<bool> convert_int_to_binary(int x);

template<typename FieldT>
FieldT string_to_field(std::string input);

std::vector<bool> address_bits_from_address(int address, int tree_depth);

// Dump a vector into an array
template<size_t Size> std::array<bool, Size> dump_vector_in_array(std::vector<bool> vect);

// Dump an array into a vector
template<size_t Size> std::vector<bool> dump_array_in_vector(std::array<bool, Size> arr);

bitsAddr get_bitsAddr_from_vector(std::vector<bool> vect);

std::vector<bool> get_vector_from_bitsAddr(bitsAddr arr);

} // libzeth

#include "util.tcc"

#endif // __ZETH_UTIL_HPP__
