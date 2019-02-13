#ifndef __ZETH_UTIL_HPP__
#define __ZETH_UTIL_HPP__

#include <vector>
#include <string>
#include <cstdint>

namespace libzeth {

template<typename T>
T swap_bit_endianness(T v);

std::vector<bool> hexadecimal_str_to_binary_vector(std::string str);
std::vector<bool> hexadecimal_digest_to_binary_vector(std::string str);

} // libzeth

#endif
