// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CIRCUITS_CIRCUIT_UTILS_HPP__
#define __ZETH_CIRCUITS_CIRCUIT_UTILS_HPP__

#include "libzeth/core/bits.hpp"

#include <libsnark/gadgetlib1/pb_variable.hpp>

namespace libzeth
{

template<typename FieldT>
libsnark::linear_combination<FieldT> packed_addition(
    const libsnark::pb_variable_array<FieldT> &input);

template<typename FieldT>
libsnark::pb_variable_array<FieldT> variable_array_from_bit_vector(
    libsnark::protoboard<FieldT> &pb,
    const std::vector<bool> &bits,
    const std::string &annotation_prefix);

} // namespace libzeth

#include "libzeth/circuits/circuit_utils.tcc"

#endif // __ZETH_CIRCUITS_CIRCUIT_UTILS_HPP__
