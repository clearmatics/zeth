// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SNARKS_API_IMPORTS_HPP__
#define __ZETH_SNARKS_API_IMPORTS_HPP__

#include "libzeth/snarks_types.hpp"

#ifdef ZKSNARK_PGHR13
#include "libzeth/snarks/pghr13/api.hpp"
namespace libzeth
{
template<typename ppT> using defaultSnarkApi = pghr13api<ppT>;
} // namespace libzeth

#elif ZKSNARK_GROTH16
#include "libzeth/snarks/groth16/api.hpp"
namespace libzeth
{
template<typename ppT> using defaultSnarkApi = groth16api<ppT>;
} // namespace libzeth

#else
#error You must define one of the SNARK_* symbols indicated into the CMakelists.txt file.
#endif

#endif // __ZETH_SNARKS_API_IMPORTS_HPP__
