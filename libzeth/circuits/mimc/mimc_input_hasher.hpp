// Copyright (c) 2015-2022 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CIRCUITS_MIMC_MIMC_INPUT_HASHER_HPP__
#define __ZETH_CIRCUITS_MIMC_MIMC_INPUT_HASHER_HPP__

#include <libsnark/gadgetlib1/gadget.hpp>

namespace libzeth
{

/// Given a list of variables, hash the variables to a value which can be used
/// as a public input bound to the original variables.
template<typename FieldT, typename compFnT>
class mimc_input_hasher : public libsnark::gadget<FieldT>
{
private:
    // Output variable
    libsnark::pb_variable<FieldT> _result;

    // Compression function constraints
    std::vector<std::shared_ptr<compFnT>> _compression_functions;

    // Intermediate values
    libsnark::pb_variable_array<FieldT> _intermediate_values;

public:
    mimc_input_hasher(
        libsnark::protoboard<FieldT> &pb,
        const libsnark::pb_linear_combination_array<FieldT> &inputs,
        const libsnark::pb_variable<FieldT> hash_output,
        const std::string &annotation_prefix);

    void generate_r1cs_constraints();
    void generate_r1cs_witness() const;

    static FieldT get_iv();
    static FieldT compute_hash(const std::vector<FieldT> &values);
};

} // namespace libzeth

#include "mimc_input_hasher.tcc"

#endif // __ZETH_CIRCUITS_MIMC_MIMC_INPUT_HASHER_HPP__
