// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SNARKS_GRPOTH16_MULTI_EXP_HPP__
#define __ZETH_SNARKS_GRPOTH16_MULTI_EXP_HPP__

#include "libzeth/core/include_libsnark.hpp"

namespace libzeth
{

template<typename ppT, typename GroupT>
GroupT multi_exp(
    typename std::vector<libff::G1<ppT>>::const_iterator gs_start,
    typename std::vector<libff::G1<ppT>>::const_iterator gs_end,
    typename std::vector<libff::Fr<ppT>>::const_iterator fs_start,
    typename std::vector<libff::Fr<ppT>>::const_iterator fs_end);

template<typename ppT, typename GroupT>
GroupT multi_exp(
    const std::vector<GroupT> &gs, const libff::Fr_vector<ppT> &fs);

} // namespace libzeth

#include "libzeth/snarks/groth16/mpc/multi_exp.tcc"

#endif // __ZETH_SNARKS_GRPOTH16_MULTI_EXP_HPP__
