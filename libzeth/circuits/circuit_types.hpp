// Copyright (c) 2015-2022 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CIRCUITS_CIRCUIT_TYPES_HPP__
#define __ZETH_CIRCUITS_CIRCUIT_TYPES_HPP__

#include "libzeth/circuits/blake2s/blake2s.hpp"
#include "libzeth/circuits/circuit_wrapper.hpp"
#include "libzeth/circuits/mimc/mimc_selector.hpp"
#include "libzeth/core/include_libsnark.hpp"

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/curves/bls12_377/bls12_377_pp.hpp>

// Types that must be common across all executable, defined once here. Outside
// of tests, these should not be set anywhere else in the code. Do not include
// this file in code that is intended to be parameterized by hash type.

namespace libzeth
{

// Hash used for the commitments and PRFs
template<typename FieldT> using HashT = BLAKE2s_256<FieldT>;

// Hash function to be used in the Merkle Tree
template<typename FieldT>
using HashTreeT = mimc_compression_function_gadget<FieldT>;

template<typename ppT, typename snarkT>
using JoinsplitCircuitT = circuit_wrapper<
    HashT<libff::Fr<ppT>>,
    HashTreeT<libff::Fr<ppT>>,
    ppT,
    snarkT,
    libzeth::ZETH_NUM_JS_INPUTS,
    libzeth::ZETH_NUM_JS_OUTPUTS,
    libzeth::ZETH_MERKLE_TREE_DEPTH>;

} // namespace libzeth

#endif // __ZETH_CIRCUITS_CIRCUIT_TYPES_HPP__
