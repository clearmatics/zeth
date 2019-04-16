#ifndef __ZETH_SNARKS_IMPORT_HPP__
#define __ZETH_SNARKS_IMPORT_HPP__

<<<<<<< HEAD
#ifdef SNARK_R1CS_PPZKSNARK
#include "snarks/pghr13/helpers.hpp"
#include "snarks/pghr13/computation.hpp"
#include "snarks/pghr13/response.hpp"

=======
#ifdef SNARK_PGHR13
#include "snarks/pghr13/pghr13_helpers.hpp"
#include "snarks/pghr13/pghr13_computation.hpp"
#include "snarks/pghr13/pghr13_response.hpp"
#elif SNARK_GROTH16
#include "snarks/groth16/groth16_helpers.hpp"
#include "snarks/groth16/groth16_computation.hpp"
#include "snarks/groth16/groth16_response.hpp"
>>>>>>> change snark variable names
#else
#error You must define one of the SNARK_* symbols indicated into the CMakelists.txt file.
#endif

#endif // __ZETH_SNARKS_IMPORT_HPP__
