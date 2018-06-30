#ifndef __CMD_SETUP_HPP__
#define __CMD_SETUP_HPP__

#include <prover/prover.hpp>
#include <prover/computation.hpp>
#include <sha256/sha256_ethereum.hpp>

int setupCommand(Miximus<FieldT, sha256_ethereum> prover);
void printUsageSetupCmd();

#endif
