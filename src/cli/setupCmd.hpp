#ifndef __CMD_SETUP_HPP__
#define __CMD_SETUP_HPP__

#include <prover/prover.hpp>
#include <prover/computation.hpp>
#include <sha256/sha256_ethereum.hpp>

void printUsageSetupCmd();
template<typename FieldT, typename HashT> int setupCommand(Miximus<FieldT, HashT> prover);

#include "setupCmd.tcc"

#endif
