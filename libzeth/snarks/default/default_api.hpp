// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SNARKS_DEFAULT_DEFAULT_API_HPP__
#define __ZETH_SNARKS_DEFAULT_DEFAULT_API_HPP__

#include "libzeth/snarks/default/default_core.hpp"

#if defined(ZKSNARK_PGHR13)
#include "libzeth/snarks/pghr13/pghr13_api.hpp"
namespace libzeth
{
template<typename ppT> using defaultSnarkApi = pghr13api<ppT>;
} // namespace libzeth

#elif defined(ZKSNARK_GROTH16)
#include "libzeth/snarks/groth16/groth16_api.hpp"
namespace libzeth
{
template<typename ppT> using defaultSnarkApi = groth16api<ppT>;
} // namespace libzeth

#else
#error No recognized SNARK_* macro defined (see CMakelists.txt).
#endif

#endif // __ZETH_SNARKS_DEFAULT_DEFAULT_API_HPP__
