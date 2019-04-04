#ifndef __ZETH_UTIL_HPP__
#define __ZETH_UTIL_HPP__

#include <vector>
#include <string>
#include <cstdint>

#include <libsnark/common/data_structures/merkle_tree.hpp>

#include "types/bits.hpp"
#include "types/note.hpp"
#include "types/joinsplit.hpp"

#include "util.pb.h"
#include "libsnark_helpers/debug_helpers.hpp"

namespace libzeth {

template<typename T>
T swap_bit_endianness(T v);

std::vector<bool> hexadecimal_str_to_binary_vector(std::string str);
std::vector<bool> hexadecimal_digest_to_binary_vector(std::string str);
bits256 hexadecimal_digest_to_bits256(std::string digest_hex_str);
bits64 hexadecimal_value_to_bits64(std::string value_hex_str);

std::vector<bool> convert_int_to_binary(int x);
std::vector<bool> address_bits_from_address(int address, int tree_depth);

//message parsing utils
libsnark::merkle_authentication_node ParseMerkleNode(std::string mk_node);
libzeth::ZethNote ParseZethNote(const proverpkg::ZethNote& note);
libzeth::JSInput ParseJSInput(const proverpkg::JSInput& input);
proverpkg::HexadecimalPointBaseGroup1Affine FormatHexadecimalPointBaseGroup1Affine(libff::alt_bn128_G1 point);
proverpkg::HexadecimalPointBaseGroup2Affine FormatHexadecimalPointBaseGroup2Affine(libff::alt_bn128_G2 point);
} // libzeth

#endif
