// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CORE_MULTI_EXP_TCC__
#define __ZETH_CORE_MULTI_EXP_TCC__

#include "libzeth/core/multi_exp.hpp"

namespace libzeth
{

template<typename FieldT, typename GroupT>
GroupT multi_exp(
    typename std::vector<GroupT>::const_iterator gs_start,
    typename std::vector<GroupT>::const_iterator gs_end,
    typename std::vector<FieldT>::const_iterator fs_start,
    typename std::vector<FieldT>::const_iterator fs_end)
{
    const libff::multi_exp_method Method = libff::multi_exp_method_BDLO12;
    return libff::multi_exp_filter_one_zero<GroupT, FieldT, Method>(
        gs_start, gs_end, fs_start, fs_end, 1);
}

template<typename ppT, typename GroupT>
GroupT multi_exp(const std::vector<GroupT> &gs, const libff::Fr_vector<ppT> &fs)
{
    assert(gs.size() >= fs.size());
    assert(gs.size() > 0);

    using Fr = libff::Fr<ppT>;
    const libff::multi_exp_method Method = libff::multi_exp_method_BDLO12;
    return libff::multi_exp_filter_one_zero<GroupT, Fr, Method>(
        gs.begin(), gs.begin() + fs.size(), fs.begin(), fs.end(), 1);
}

} // namespace libzeth

#endif // __ZETH_CORE_MULTI_EXP_TCC__
