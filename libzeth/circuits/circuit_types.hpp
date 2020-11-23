// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CIRCUITS_CIRCUIT_TYPES_HPP__
#define __ZETH_CIRCUITS_CIRCUIT_TYPES_HPP__

#include "libzeth/circuits/blake2s/blake2s.hpp"
#include "libzeth/circuits/circuit_wrapper.hpp"
#include "libzeth/circuits/mimc/mimc_mp.hpp"
#include "libzeth/core/include_libsnark.hpp"

// Types that must be common across all executable, defined once here. Outside
// of tests, these should not be set anywhere else in the code. Do not include
// this file in code that is intended to be parameterized by hash type.

namespace libzeth
{

// Hash used for the commitments and PRFs
template<typename FieldT> using HashT = BLAKE2s_256<FieldT>;

// Hash function to be used in the Merkle Tree
template<typename FieldT>
using HashTreeT = MiMC_mp_gadget<FieldT, MiMCe7_permutation_gadget<FieldT>>;

} // namespace libzeth

#endif // __ZETH_CIRCUITS_CIRCUIT_TYPES_HPP__
