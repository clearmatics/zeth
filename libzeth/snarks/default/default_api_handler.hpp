// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SNARKS_DEFAULT_DEFAULT_API_HANDLER_HPP__
#define __ZETH_SNARKS_DEFAULT_DEFAULT_API_HANDLER_HPP__

#include "libzeth/snarks/default/default_snark.hpp"

#if defined(ZKSNARK_PGHR13)
#include "libzeth/snarks/pghr13/pghr13_api_handler.hpp"
namespace libzeth
{
template<typename ppT> using default_api_handler = pghr13_api_handler<ppT>;
} // namespace libzeth

#elif defined(ZKSNARK_GROTH16)
#include "libzeth/snarks/groth16/groth16_api_handler.hpp"
namespace libzeth
{
template<typename ppT> using default_api_handler = groth16_api_handler<ppT>;
} // namespace libzeth

#else
#error No recognized SNARK_* macro defined (see CMakelists.txt).
#endif

#endif // __ZETH_SNARKS_DEFAULT_DEFAULT_API_HANDLER_HPP__
