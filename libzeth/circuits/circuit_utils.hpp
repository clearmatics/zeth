// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CIRCUITS_CIRCUITS_UTILS_HPP__
#define __ZETH_CIRCUITS_CIRCUITS_UTILS_HPP__

#include "libzeth/types/bits.hpp"

#include <libsnark/gadgetlib1/pb_variable.hpp>

namespace libzeth
{

std::vector<bool> convert_to_binary(size_t n);

template<typename FieldT>
libsnark::linear_combination<FieldT> packed_addition(
    libsnark::pb_variable_array<FieldT> input);
template<typename FieldT>
libsnark::pb_variable_array<FieldT> from_bits(
    std::vector<bool> bits, const libsnark::pb_variable<FieldT> &ZERO);

} // namespace libzeth

#include "libzeth/circuits/circuit_utils.tcc"

#endif // __ZETH_CIRCUITS_CIRCUITS_UTILS_HPP__
