#ifndef __ZETH_SNARKS_IMPORT_HPP__
#define __ZETH_SNARKS_IMPORT_HPP__

#ifdef SNARK_R1CS_PPZKSNARK
#include "snarks/pghr13/pghr13_helpers.hpp"
#include "snarks/pghr13/pghr13_computation.hpp"
#include "snarks/pghr13/pghr13_response.hpp"
#elif SNARK_R1CS_GG_PPZKSNARK
#include "snarks/groth16/groth16_helpers.hpp"
#include "snarks/groth16/groth16_computation.hpp"
#include "snarks/groth16/groth16_response.hpp"
#else
#error You must define one of the SNARK_* symbols indicated into the CMakelists.txt file.
#endif

#endif