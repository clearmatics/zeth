#ifndef __ZETH_UTIL_HPP__
#define __ZETH_UTIL_HPP__

#include "types/bits.hpp"

#include <cstdint>
#include <gmp.h>
#include <libff/algebra/fields/bigint.hpp>
#include <string>
#include <vector>

namespace libzeth
{

template<typename T> T swap_bit_endianness(T v);

std::vector<bool> hex_to_binary_vector(std::string str);
std::vector<bool> hex_digest_to_binary_vector(std::string str);
bits256 hex_digest_to_bits256(std::string digest_hex_str);
bits64 hex_value_to_bits64(std::string value_hex_str);

std::vector<bool> convert_int_to_binary(int x);
std::vector<bool> address_bits_from_address(int address, size_t tree_depth);

template<typename FieldT> FieldT string_to_field(std::string input);

} // namespace libzeth
#include "util.tcc"

#endif // __ZETH_UTIL_HPP__
