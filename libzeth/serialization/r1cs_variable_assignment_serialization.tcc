// Copyright (c) 2015-2022 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SERIALIZATION_R1CS_VARIABLE_ASSIGNMENT_SERIALIZATION_TCC__
#define __ZETH_SERIALIZATION_R1CS_VARIABLE_ASSIGNMENT_SERIALIZATION_TCC__

#include "libzeth/core/field_element_utils.hpp"
#include "libzeth/serialization/r1cs_variable_assignment_serialization.hpp"
#include "libzeth/serialization/stream_utils.hpp"

namespace libzeth
{

template<typename FieldT>
void r1cs_variable_assignment_read_bytes(
    libsnark::r1cs_variable_assignment<FieldT> &assignment, std::istream &in_s)
{
    collection_read_bytes<
        libsnark::r1cs_variable_assignment<FieldT>,
        field_element_read_bytes<FieldT>>(assignment, in_s);
}

template<typename FieldT>
void r1cs_variable_assignment_read_bytes(
    libsnark::r1cs_primary_input<FieldT> &primary,
    libsnark::r1cs_auxiliary_input<FieldT> &auxiliary,
    const size_t primary_input_size,
    std::istream &in_s)
{
    // Manually read the collection size, compute the primary and auxiliary
    // sizes and read into the separate arrays.
    const size_t n = read_bytes<size_t>(in_s);
    if (n < primary_input_size) {
        throw std::length_error(
            "assignment length smaller than primary input size");
    }

    primary.clear();
    collection_n_read_bytes<
        libsnark::r1cs_primary_input<FieldT>,
        field_element_read_bytes<FieldT>>(primary, primary_input_size, in_s);

    auxiliary.clear();
    collection_n_read_bytes<
        libsnark::r1cs_auxiliary_input<FieldT>,
        field_element_read_bytes<FieldT>>(
        auxiliary, n - primary_input_size, in_s);
}

template<typename FieldT>
void r1cs_variable_assignment_write_bytes(
    const libsnark::r1cs_variable_assignment<FieldT> &assignment,
    std::ostream &out_s)
{
    collection_write_bytes<
        libsnark::r1cs_variable_assignment<FieldT>,
        field_element_write_bytes<FieldT>>(assignment, out_s);
}

template<typename FieldT>
void r1cs_variable_assignment_write_bytes(
    const libsnark::r1cs_primary_input<FieldT> &primary,
    const libsnark::r1cs_auxiliary_input<FieldT> &auxiliary,
    std::ostream &out_s)
{
    // Manually write out the aggregation of primary and auxiliary as a single
    // collection.
    const size_t total_size = primary.size() + auxiliary.size();
    write_bytes(total_size, out_s);
    collection_n_write_bytes<
        libsnark::r1cs_primary_input<FieldT>,
        field_element_write_bytes>(primary, primary.size(), out_s);
    collection_n_write_bytes<
        libsnark::r1cs_primary_input<FieldT>,
        field_element_write_bytes>(auxiliary, auxiliary.size(), out_s);
}

} // namespace libzeth

#endif // __ZETH_SERIALIZATION_R1CS_VARIABLE_ASSIGNMENT_SERIALIZATION_TCC__
