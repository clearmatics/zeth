// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SERIALIZATION_SNARKS_API_IMPORTS_HPP__
#define __ZETH_SERIALIZATION_SNARKS_API_IMPORTS_HPP__

#ifdef ZKSNARK_PGHR13
#include "libzeth/serialization/api/snarks/pghr13.hpp"
#elif ZKSNARK_GROTH16
#include "libzeth/serialization/api/snarks/groth16.hpp"
#else
#error You must define one of the SNARK_* symbols indicated into the CMakelists.txt file.
#endif

#endif // __ZETH_SERIALIZATION_SNARKS_API_IMPORTS_HPP__
