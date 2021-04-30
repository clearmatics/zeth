// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CIRCUITS_CIRCUIT_TYPES_HPP__
#define __ZETH_CIRCUITS_CIRCUIT_TYPES_HPP__

#include "libzeth/circuits/blake2s/blake2s.hpp"
#include "libzeth/circuits/circuit_wrapper.hpp"
#include "libzeth/circuits/mimc/mimc_mp.hpp"
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

// Hash function selection, parameterized by pairing.
template<typename FieldT> class tree_hash_selector
{
};

// For alt-bn128, use MiMC17 with 65 rounds.
template<> class tree_hash_selector<libff::alt_bn128_Fr>
{
public:
    using tree_hash = MiMC_mp_gadget<
        libff::alt_bn128_Fr,
        MiMC_permutation_gadget<libff::alt_bn128_Fr, 17, 65>>;
};

// For bls12-377, use MiMC17 with 62 rounds
template<> class tree_hash_selector<libff::bls12_377_Fr>
{
public:
    using tree_hash = MiMC_mp_gadget<
        libff::bls12_377_Fr,
        MiMC_permutation_gadget<libff::bls12_377_Fr, 17, 62>>;
};

// Hash function to be used in the Merkle Tree
template<typename FieldT>
using HashTreeT = typename tree_hash_selector<FieldT>::tree_hash;

} // namespace libzeth

#endif // __ZETH_CIRCUITS_CIRCUIT_TYPES_HPP__
