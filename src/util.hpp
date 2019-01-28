#ifndef __ZETH_UTIL_HPP__
#define __ZETH_UTIL_HPP__

#include <vector>
#include <cstdint>

std::vector<bool> swap_bit_endianness(std::vector<bool> v);
std::vector<bool> hexadecimal_digest_to_binary_vector(char* str);

#endif
