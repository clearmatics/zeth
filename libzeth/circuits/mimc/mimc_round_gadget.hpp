// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CIRCUITS_MIMC_ROUND_GADGET_HPP__
#define __ZETH_CIRCUITS_MIMC_ROUND_GADGET_HPP__

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
        bit_utils<Exponent>::bit_size() + bit_utils<Exponent>::hamming_weight() -
        2;

    // Message of the current round
    const libsnark::pb_variable<FieldT> _x;

    // Key of the current round
    const libsnark::pb_variable<FieldT> _k;

    // Round constant of the current round
    const FieldT _c;

    // Result variable
    const libsnark::pb_variable<FieldT> _result;

    // Boolean variable to add the key after the round
    const bool _add_k_to_result;

    // Intermediate values
    std::vector<libsnark::pb_variable<FieldT>> _exponents;

public:
    MiMC_round_gadget(
        libsnark::protoboard<FieldT> &pb,
        const libsnark::pb_variable<FieldT> &x,
        const libsnark::pb_variable<FieldT> &k,
        const FieldT &c,
        libsnark::pb_variable<FieldT> &result,
        const bool add_k_to_result,
        const std::string &annotation_prefix = "MiMC_round_gadget");

    void generate_r1cs_constraints();
    void generate_r1cs_witness() const;
};

} // namespace libzeth

#include "libzeth/circuits/mimc/mimc_round_gadget.tcc"

#endif // __ZETH_CIRCUITS_MIMC_ROUND_GADGET_HPP__
