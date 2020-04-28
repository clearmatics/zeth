// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CORE_MULTI_EXP_HPP__
#define __ZETH_CORE_MULTI_EXP_HPP__

#include "libzeth/core/include_libff.hpp"

namespace libzeth
{

template<typename fieldT, typename groupT>
groupT multi_exp(
    typename std::vector<groupT>::const_iterator gs_start,
    typename std::vector<groupT>::const_iterator gs_end,
    typename std::vector<fieldT>::const_iterator fs_start,
    typename std::vector<fieldT>::const_iterator fs_end);

template<typename ppT, typename groupT>
groupT multi_exp(
    const std::vector<groupT> &gs, const libff::Fr_vector<ppT> &fs);

} // namespace libzeth

#include "libzeth/core/multi_exp.tcc"

#endif // __ZETH_CORE_MULTI_EXP_HPP__
