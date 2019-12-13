// Copyright (c) 2015-2019 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SNARKS_API_IMPORTS_HPP__
#define __ZETH_SNARKS_API_IMPORTS_HPP__

#ifdef ZKSNARK_PGHR13
#include "snarks/pghr13/api/response.hpp"
#elif ZKSNARK_GROTH16
#include "snarks/groth16/api/response.hpp"
#else
#error You must define one of the SNARK_* symbols indicated into the CMakelists.txt file.
#endif

#endif // __ZETH_SNARKS_API_IMPORTS_HPP__
