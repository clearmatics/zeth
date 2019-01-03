#include <prover/prover.hpp>
#include <prover/computation.hpp>
#include <sha256/sha256_ethereum.hpp>

#include "proveCmd.hpp"

void printUsageProveCmd() {
    std::cerr << "Invalid number of arguments" << std::endl;
    std::cerr << "Usage: " << std::endl;
    std::cerr << "\t" << "zeth prove [tree_depth] [commitment_address] [secret] [nullifier] [commitment] [root] [merkle path (from top to bottom)...]" << std::endl;
}
