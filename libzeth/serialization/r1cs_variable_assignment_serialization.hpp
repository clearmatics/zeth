// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SERIALIZATION_R1CS_VARIABLE_ASSIGNMENT_SERIALIZATION_HPP__
#define __ZETH_SERIALIZATION_R1CS_VARIABLE_ASSIGNMENT_SERIALIZATION_HPP__

#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>

namespace libzeth
{

template<typename FieldT>
void r1cs_variable_assignment_read_bytes(
    libsnark::r1cs_variable_assignment<FieldT> &assignment, std::istream &in_s);

template<typename FieldT>
void r1cs_variable_assignment_write_bytes(
    const libsnark::r1cs_variable_assignment<FieldT> &assignment,
    std::ostream &out_s);

} // namespace libzeth

#include "libzeth/serialization/r1cs_variable_assignment_serialization.tcc"

#endif // __ZETH_SERIALIZATION_R1CS_VARIABLE_ASSIGNMENT_SERIALIZATION_HPP__
