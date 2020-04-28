// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CIRCUITS_CIRCUIT_TYPES_HPP__
#define __ZETH_CIRCUITS_CIRCUIT_TYPES_HPP__

#include "libzeth/circuits/blake2s/blake2s.hpp"
#include "libzeth/circuits/circuit_wrapper.hpp"
#include "libzeth/include_libsnark.hpp"

// Types that must be common across all executable, defined once here. Outside
// of tests, these should not be set anywhere else in the code. Do not include
// this file in code that is generic (parameterized on ppT or FieldT).

namespace libzeth
{

// Use the pairing from build configuration
using ppT = libff::default_ec_pp;

// Field type for the pairing.
using FieldT = libff::Fr<ppT>;

// Hash used for the commitments and PRFs
using HashT = BLAKE2s_256<FieldT>;

// Hash function to be used in the Merkle Tree
using HashTreeT = MiMC_mp_gadget<FieldT>;

} // namespace libzeth

#endif // __ZETH_CIRCUITS_CIRCUIT_TYPES_HPP__
