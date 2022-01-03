// Copyright (c) 2015-2022 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CIRCUITS_MIMC_ROUND_HPP__
#define __ZETH_CIRCUITS_MIMC_ROUND_HPP__

#include "libzeth/circuits/circuit_utils.hpp"
#include "libzeth/core/utils.hpp"

#include <libsnark/gadgetlib1/gadget.hpp>

namespace libzeth
{

template<typename FieldT, size_t Exponent>
class MiMC_round_gadget : public libsnark::gadget<FieldT>
{
private:
    static_assert((Exponent & 1) == 1, "MiMC Exponent must be odd");

    static constexpr size_t EXPONENT_NUM_BITS = bit_utils<Exponent>::bit_size();
    static constexpr size_t NUM_CONDITIONS =
        bit_utils<Exponent>::bit_size() +
        bit_utils<Exponent>::hamming_weight() - 2;

    // Message of the current round
    const libsnark::pb_linear_combination<FieldT> msg;

    // Key of the current round
    const libsnark::pb_linear_combination<FieldT> key;

    // Round constant of the current round
    const FieldT round_const;

    // Result variable
    const libsnark::pb_variable<FieldT> result;

    // Optional linear combination to add after the final round
    const libsnark::pb_linear_combination<FieldT> add_to_result;

    // Flag indicating whether add_to_result is valid
    const bool add_to_result_is_valid;

    // Intermediate values
    std::vector<libsnark::pb_variable<FieldT>> exponents;

    // Initialization code shared by constructors.
    void initialize();

public:
    MiMC_round_gadget(
        libsnark::protoboard<FieldT> &pb,
        const libsnark::pb_linear_combination<FieldT> &msg,
        const libsnark::pb_linear_combination<FieldT> &key,
        const FieldT &round_const,
        libsnark::pb_variable<FieldT> &result,
        const std::string &annotation_prefix = "MiMC_round_gadget");

    /// Constructor that supports adding some linear_combination to the final
    /// result.
    MiMC_round_gadget(
        libsnark::protoboard<FieldT> &pb,
        const libsnark::pb_linear_combination<FieldT> &msg,
        const libsnark::pb_linear_combination<FieldT> &key,
        const FieldT &round_const,
        libsnark::pb_variable<FieldT> &result,
        const libsnark::pb_linear_combination<FieldT> &add_to_result,
        const std::string &annotation_prefix = "MiMC_round_gadget");

    void generate_r1cs_constraints();
    void generate_r1cs_witness() const;
};

} // namespace libzeth

#include "libzeth/circuits/mimc/mimc_round.tcc"

#endif // __ZETH_CIRCUITS_MIMC_ROUND_HPP__
