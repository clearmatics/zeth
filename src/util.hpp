#ifndef __ZETH_UTIL_HPP__
#define __ZETH_UTIL_HPP__

#include <vector>
#include <string>
#include <cstdint>

#include "types/bits.hpp"

namespace libzeth {

template<typename T>
T swap_bit_endianness(T v);

std::vector<bool> convert_int_to_binary(int x);

template<typename FieldT>
FieldT string_to_field(std::string input);

std::vector<bool> address_bits_from_address(int address, int tree_depth);

} // libzeth

#include "util.tcc"

#endif // __ZETH_UTIL_HPP__
