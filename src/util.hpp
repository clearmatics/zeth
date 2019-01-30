#ifndef __ZETH_UTIL_HPP__
#define __ZETH_UTIL_HPP__

#include <vector>
#include <cstdint>

template<typename T>
T swap_bit_endianness(T v);

std::vector<bool> hexadecimal_str_to_binary_vector(char* str);
std::vector<bool> hexadecimal_digest_to_binary_vector(char* str);

#endif
