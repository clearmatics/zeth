#ifndef __CMD_PROVE_HPP__
#define __CMD_PROVE_HPP__

#include <iostream>

#include <libsnark_helpers/libsnark_helpers.hpp>
#include <prover/prover.hpp>
#include <prover/computation.hpp>
#include <sha256/sha256_ethereum.hpp>

// We need to access the merkle_authentication_node declaration
#include <libsnark/common/data_structures/merkle_tree.hpp>
#include "cli_utils.hpp"

void printUsageProveCmd();
template<typename ppT, typename HashT> int proveCommand(Miximus<ppT, HashT> prover, int argc, char* argv[]);

#include "proveCmd.tcc"

#endif
