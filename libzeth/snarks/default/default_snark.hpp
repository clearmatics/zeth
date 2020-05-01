// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SNARKS_DEFAULT_DEFAULT_SNARK_HPP__
#define __ZETH_SNARKS_DEFAULT_DEFAULT_SNARK_HPP__

#if defined(ZKSNARK_PGHR13)
#include "libzeth/snarks/pghr13/pghr13_snark.hpp"
namespace libzeth
{
template<typename ppT> using default_snark = pghr13_snark<ppT>;
} // namespace libzeth

#elif defined(ZKSNARK_GROTH16)
#include "libzeth/snarks/groth16/groth16_snark.hpp"
namespace libzeth
{
template<typename ppT> using default_snark = groth16_snark<ppT>;
} // namespace libzeth

#else
#error No recognized SNARK_* macro defined (see CMakelists.txt).
#endif

#endif // __ZETH_SNARKS_DEFAULT_DEFAULT_SNARK_HPP__
