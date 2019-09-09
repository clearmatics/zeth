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

std::string hexadecimal_str_to_binary_str(const std::string &s);
std::string binary_str_to_hexadecimal_str(const void *s, const size_t size);
std::string binary_str_to_hexadecimal_str(const std::string &s);

// Attempt to find the default trusted setup path, given by env variables or
// fallback.
std::string trusted_setup_path(const std::string &fallback = "");

// Check for environment variables defining the location of a specific file
// related to trusted setup.
std::string trusted_setup_file(const std::string &file_name);

template<typename V> bool container_is_well_formed(const V &values);
template<typename T> void check_well_formed(const T &v, const char *name);
template<typename T> void check_well_formed_(const T &v, const char *name);

} // namespace libzeth
#include "util.tcc"

#endif // __ZETH_UTIL_HPP__
