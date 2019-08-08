#ifndef __ZETH_UTIL_HPP__
#define __ZETH_UTIL_HPP__

#include <vector>
#include <string>
#include <cstdint>
#include <gmp.h>

#include "types/bits.hpp"
#include <libff/algebra/fields/bigint.hpp>

namespace libzeth {

template<typename T>
T swap_bit_endianness(T v);

std::vector<bool> hexadecimal_str_to_binary_vector(std::string str);
std::vector<bool> hexadecimal_digest_to_binary_vector(std::string str);
bits256 hexadecimal_digest_to_bits256(std::string digest_hex_str);
bits64 hexadecimal_value_to_bits64(std::string value_hex_str);

std::vector<bool> convert_int_to_binary(int x);
std::vector<bool> address_bits_from_address(int address, int tree_depth);

template<typename FieldT>
FieldT string_to_field(std::string input);

} // libzeth
#include "util.tcc"

#endif
