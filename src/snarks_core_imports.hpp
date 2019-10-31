#ifndef __ZETH_SNARKS_CORE_IMPORTS_HPP__
#define __ZETH_SNARKS_CORE_IMPORTS_HPP__

#ifdef ZKSNARK_PGHR13
#include "snarks/pghr13/computation.hpp"
#include "snarks/pghr13/helpers.hpp"
#elif ZKSNARK_GROTH16
#include "snarks/groth16/computation.hpp"
#include "snarks/groth16/helpers.hpp"
#include "snarks/groth16/mpc_utils.hpp"
#else
#error You must define one of the SNARK_* symbols indicated into the CMakelists.txt file.
#endif

#endif // __ZETH_SNARKS_CORE_IMPORTS_HPP__
