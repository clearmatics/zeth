// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CIRCUITS_MIMC_MIMC_INPUT_HASHER_TCC__
#define __ZETH_CIRCUITS_MIMC_MIMC_INPUT_HASHER_TCC__

#include "mimc_input_hasher.hpp"

namespace libzeth
{

template<typename FieldT, typename compFnT>
mimc_input_hasher<FieldT, compFnT>::mimc_input_hasher(
    libsnark::protoboard<FieldT> &pb,
    const libsnark::pb_linear_combination_array<FieldT> &inputs,
    const libsnark::pb_variable<FieldT> result,
    const std::string &annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix), _result(result)
{
    const size_t num_inputs = inputs.size();
    if (num_inputs < 2) {
        // Although it would be superfluous, we could support 1 entry. However
        // it would add some complexity to the code below. For now, assume
        // strictly more than 1 entry.
        throw std::invalid_argument(
            "inputs array must have at least 2 entries");
    }

    // Require one compression function invocation per element in the array,
    // followed by the finalization step. Each invocation except the last
    // requires an intermediate output variable.
    _compression_functions.reserve(num_inputs + 1);
    _intermediate_values.allocate(
        pb, num_inputs, FMT(annotation_prefix, "intermediate_values"));

    libsnark::pb_linear_combination<FieldT> iv;
    iv.assign(pb, get_iv());

    // First step: hash_output[0] <- mimc_mp(iv, i[0])

    _compression_functions.emplace_back(new compFnT(
        pb,
        iv,
        inputs[0],
        _intermediate_values[0],
        FMT(annotation_prefix, " compression_functions[0]")));

    // Intermediate invocations of the compression function.
    for (size_t i = 1; i < num_inputs; ++i) {
        _compression_functions.emplace_back(new compFnT(
            pb,
            _intermediate_values[i - 1],
            inputs[i],
            _intermediate_values[i],
            FMT(annotation_prefix, " compression_functions[%zu]", i)));
    }

    // Last invocation of compression function to finalize.
    libsnark::pb_linear_combination<FieldT> num_inputs_lc;
    num_inputs_lc.assign(pb, FieldT(num_inputs));
    _compression_functions.emplace_back(new compFnT(
        pb,
        _intermediate_values[num_inputs - 1],
        num_inputs_lc,
        result,
        FMT(annotation_prefix, " compression_functions[%zu]", num_inputs)));

    assert(_compression_functions.size() == num_inputs + 1);
}

template<typename FieldT, typename compFnT>
void mimc_input_hasher<FieldT, compFnT>::generate_r1cs_constraints()
{
    for (const std::shared_ptr<compFnT> &cf : _compression_functions) {
        cf->generate_r1cs_constraints();
    }
}

template<typename FieldT, typename compFnT>
void mimc_input_hasher<FieldT, compFnT>::generate_r1cs_witness() const
{
    for (const std::shared_ptr<compFnT> &cf : _compression_functions) {
        cf->generate_r1cs_witness();
    }
}

template<typename FieldT, typename compFnT>
FieldT mimc_input_hasher<FieldT, compFnT>::get_iv()
{
    // IV generated as:
    //   zeth.core.mimc._keccak_256(
    //       zeth.core.mimc._str_to_bytes("clearmatics_hash_seed"))
    // See: client/zeth/core/mimc.py
    return FieldT(
        "1319653706411738841819622385631198771438854383955240040834092139"
        "7545324034315");
}

template<typename FieldT, typename compFnT>
FieldT mimc_input_hasher<FieldT, compFnT>::compute_hash(
    const std::vector<FieldT> &values)
{
    FieldT h = get_iv();
    for (const FieldT &v : values) {
        h = compFnT::get_hash(h, v);
    }
    return compFnT::get_hash(h, FieldT(values.size()));
}

} // namespace libzeth

#endif // __ZETH_CIRCUITS_MIMC_MIMC_INPUT_HASHER_TCC__
