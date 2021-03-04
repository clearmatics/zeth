// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SERIALIZATION_R1CS_VARIABLE_ASSIGNMENT_SERIALIZATION_TCC__
#define __ZETH_SERIALIZATION_R1CS_VARIABLE_ASSIGNMENT_SERIALIZATION_TCC__

#include "libzeth/core/field_element_utils.hpp"
#include "libzeth/serialization/r1cs_variable_assignment_serialization.hpp"

namespace libzeth
{

template<typename FieldT>
void r1cs_variable_assignment_read_bytes(
    libsnark::r1cs_variable_assignment<FieldT> &assignment, std::istream &in_s)
{
    const size_t num_values = read_bytes<size_t>(in_s);
    assignment.clear();
    assignment.reserve(num_values);
    for (size_t i = 0; i < num_values; ++i) {
        assignment.push_back(FieldT());
        field_element_read_bytes(assignment.back(), in_s);
    }
}

template<typename FieldT>
void r1cs_variable_assignment_write_bytes(
    const libsnark::r1cs_variable_assignment<FieldT> &assignment,
    std::ostream &out_s)
{
    write_bytes(assignment.size(), out_s);
    for (const FieldT &value : assignment) {
        field_element_write_bytes(value, out_s);
    }
}

} // namespace libzeth

#endif // __ZETH_SERIALIZATION_R1CS_VARIABLE_ASSIGNMENT_SERIALIZATION_TCC__
