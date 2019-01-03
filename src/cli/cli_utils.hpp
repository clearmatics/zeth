#ifndef __CLI_UTILS_HPP__
#define __CLI_UTILS_HPP__

#include <libff/common/utils.hpp>
#include <algorithm>

libff::bit_vector addressBitsFromAddress(int address, int tree_depth, int *error);
std::vector<bool> convertIntToBinary(int x);
libff::bit_vector hexadecimalToBinaryVector(char* str, int* error);
int checkNbArgs(int nbArgs, int expectedNbArgs, char* args[]);

#endif
