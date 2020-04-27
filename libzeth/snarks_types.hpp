// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SNARKS_ALIAS_HPP__
#define __ZETH_SNARKS_ALIAS_HPP__

#if defined(ZKSNARK_PGHR13)
#define LIBZETH_SNARK_DEFINED
#include "libsnark/snarks/pghr13/core.hpp"
namespace libzeth
{
template<typename ppT> using defaultSnark = pghr13snark<ppT>;
} // namespace libzeth

#elif defined(ZKSNARK_GROTH16)
#define LIBZETH_SNARK_DEFINED
#include "libzeth/snarks/groth16/core.hpp"
namespace libzeth
{
template<typename ppT> using defaultSnark = groth16snark<ppT>;
} // namespace libzeth

#else
#error You must define one of the SNARK_* symbols indicated into the CMakelists.txt file.
#endif

#endif // __ZETH_SNARKS_ALIAS_HPP__
