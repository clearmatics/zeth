// Copyright (c) 2015-2022 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CIRCUITS_MIMC_MIMC_SELECTOR_HPP__
#define __ZETH_CIRCUITS_MIMC_MIMC_SELECTOR_HPP__

#include "libzeth/circuits/mimc/mimc_mp.hpp"

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/curves/bls12_377/bls12_377_pp.hpp>
#include <libff/algebra/curves/bw6_761/bw6_761_pp.hpp>
#include <libff/algebra/curves/mnt/mnt4/mnt4_pp.hpp>
#include <libff/algebra/curves/mnt/mnt6/mnt6_pp.hpp>

namespace libzeth
{

/// Instances of this class should expose a public type
/// `compression_function_gadget` which is the MiMC compression function gadget
/// with suitable exponent and number of rounds for FieldT. See
/// scripts/mimc_constraints.sage for details.
template<typename FieldT> class mimc_compression_function_selector;

// For alt-bn128, use MiMC17 with 65 rounds.
template<> class mimc_compression_function_selector<libff::alt_bn128_Fr>
{
public:
    using compression_function_gadget = MiMC_mp_gadget<
        libff::alt_bn128_Fr,
        MiMC_permutation_gadget<libff::alt_bn128_Fr, 17, 65>>;
};

// For bls12-377, use MiMC17 with 62 rounds.
template<> class mimc_compression_function_selector<libff::bls12_377_Fr>
{
public:
    using compression_function_gadget = MiMC_mp_gadget<
        libff::bls12_377_Fr,
        MiMC_permutation_gadget<libff::bls12_377_Fr, 17, 62>>;
};

// For bw6-761, use MiMC17 with 93 rounds.
template<> class mimc_compression_function_selector<libff::bw6_761_Fr>
{
public:
    using compression_function_gadget = libzeth::MiMC_mp_gadget<
        libff::bw6_761_Fr,
        MiMC_permutation_gadget<libff::bw6_761_Fr, 17, 93>>;
};

// For MNT4, use MiMC17 with 73 rounds.
template<> class mimc_compression_function_selector<libff::mnt4_Fr>
{
public:
    using compression_function_gadget = libzeth::MiMC_mp_gadget<
        libff::mnt4_Fr,
        MiMC_permutation_gadget<libff::mnt4_Fr, 17, 73>>;
};

// For MNT6, use MiMC17 with 73 rounds.
template<> class mimc_compression_function_selector<libff::mnt6_Fr>
{
public:
    using compression_function_gadget = libzeth::MiMC_mp_gadget<
        libff::mnt6_Fr,
        MiMC_permutation_gadget<libff::mnt6_Fr, 17, 73>>;
};

template<typename FieldT>
using mimc_compression_function_gadget =
    typename mimc_compression_function_selector<
        FieldT>::compression_function_gadget;

} // namespace libzeth

#endif // __ZETH_CIRCUITS_MIMC_MIMC_SELECTOR_HPP__
