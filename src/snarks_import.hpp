#ifndef __ZETH_SNARKS_IMPORT_HPP__
#define __ZETH_SNARKS_IMPORT_HPP__

#ifdef SNARK_R1CS_PPZKSNARK
#include "snarks/pghr13/helpers.hpp"
#include "snarks/pghr13/computation.hpp"
#include "snarks/pghr13/response.hpp"

#else
#error You must define one of the SNARK_* symbols indicated into the CMakelists.txt file.
#endif

#endif // __ZETH_SNARKS_IMPORT_HPP__
