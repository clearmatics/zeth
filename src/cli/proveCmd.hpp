#ifndef __CMD_PROVE_HPP__
#define __CMD_PROVE_HPP__

#include <iostream>

#include <libsnark_helpers/libsnark_helpers.hpp>
#include <prover/prover.hpp>
#include <prover/computation.hpp>
#include <sha256/sha256_ethereum.hpp>

// We need to access the merkle_authentication_node declaration
#include <libsnark/common/data_structures/merkle_tree.hpp>

int proveCommand(int argc, char* argv[], Miximus<FieldT, sha256_ethereum> prover);
void printUsageProveCmd();
int checkNbArgs(int nbArgs, char* args[]);
libff::bit_vector addressBitsFromAddress(int address, int tree_depth, int *error);
std::vector<bool> convertIntToBinary(int x);
libff::bit_vector hexadecimalToBinaryVector(char* str, int* error);

#endif
