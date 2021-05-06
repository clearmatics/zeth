// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CIRCUITS_MIMC_ROUND_TCC__
#define __ZETH_CIRCUITS_MIMC_ROUND_TCC__

#include "libzeth/circuits/mimc/mimc_round.hpp"

namespace libzeth
{

template<typename FieldT, size_t Exponent>
void MiMC_round_gadget<FieldT, Exponent>::initialize()
{
    // Each condition requires an intermediate variable, except the final one,
    // which uses _result (and optionally _k).
    exponents.resize(NUM_CONDITIONS - 1);
}

template<typename FieldT, size_t Exponent>
MiMC_round_gadget<FieldT, Exponent>::MiMC_round_gadget(
    libsnark::protoboard<FieldT> &pb,
    const libsnark::pb_linear_combination<FieldT> &msg,
    const libsnark::pb_linear_combination<FieldT> &key,
    const FieldT &round_const,
    libsnark::pb_variable<FieldT> &result,
    const std::string &annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix)
    , msg(msg)
    , key(key)
    , round_const(round_const)
    , result(result)
    , add_to_result_is_valid(false)
{
    initialize();
}

template<typename FieldT, size_t Exponent>
MiMC_round_gadget<FieldT, Exponent>::MiMC_round_gadget(
    libsnark::protoboard<FieldT> &pb,
    const libsnark::pb_linear_combination<FieldT> &msg,
    const libsnark::pb_linear_combination<FieldT> &key,
    const FieldT &round_const,
    libsnark::pb_variable<FieldT> &result,
    const libsnark::pb_linear_combination<FieldT> &add_to_result,
    const std::string &annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix)
    , msg(msg)
    , key(key)
    , round_const(round_const)
    , result(result)
    , add_to_result(add_to_result)
    , add_to_result_is_valid(true)
{
    initialize();
}

template<typename FieldT, size_t Exponent>
void MiMC_round_gadget<FieldT, Exponent>::generate_r1cs_constraints()
{
    // Mask to capture the most significant bit (the "current" bit when
    // iterating from most to least significant).
    constexpr size_t mask = 1 << (EXPONENT_NUM_BITS - 1);
    // t = x + k + c
    libsnark::pb_linear_combination<FieldT> t;
    t.assign(this->pb, msg + key + round_const);

    // For first bit (1 by definition) compute t^2
    size_t exp = Exponent << 1;
    exponents[0].allocate(
        this->pb, FMT(this->annotation_prefix, " exponents[0]"));
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(t, t, exponents[0]),
        FMT(this->annotation_prefix, " calc_t^2"));

    size_t exp_idx = 1;
    libsnark::pb_variable<FieldT> *last = &exponents[0];

    // Square-and-multiply based on all bits up to the final (lowest-order) bit.
    for (size_t i = 1; i < EXPONENT_NUM_BITS - 1; ++i) {
        if (exp & mask) {
            // last = last * t
            const size_t new_exp = exp >> (EXPONENT_NUM_BITS - 1);
            exponents[exp_idx].allocate(
                this->pb,
                FMT(this->annotation_prefix, " exponents[%zu]", exp_idx));
            this->pb.add_r1cs_constraint(
                libsnark::r1cs_constraint<FieldT>(t, *last, exponents[exp_idx]),
                FMT(this->annotation_prefix, " calc_t^%zu", new_exp));
            last = &exponents[exp_idx];
            ++exp_idx;
        }

        // last = last * last
        const size_t new_exp = 2 * (exp >> (EXPONENT_NUM_BITS - 1));
        exponents[exp_idx].allocate(
            this->pb, FMT(this->annotation_prefix, " exponents[%zu]", exp_idx));
        this->pb.add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(*last, *last, exponents[exp_idx]),
            FMT(this->annotation_prefix, " calc_t^%zu", new_exp));
        last = &exponents[exp_idx];
        ++exp_idx;

        // Shift to capture the next bit by mask.
        exp = exp << 1;
    }
    assert(exp_idx == exponents.size());

    // Final multiply (lowest-order bit is known to be 1),
    if (add_to_result_is_valid) {
        // addition of add_to_result:
        //      result = last * t + add_to_result
        //  <=> result - add_to_result = last * t
        this->pb.add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(*last, t, result - add_to_result),
            FMT(this->annotation_prefix,
                " calc_t^%zu_add_to_result",
                Exponent));
    } else {
        this->pb.add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(*last, t, result),
            FMT(this->annotation_prefix, " calc_t^%zu", Exponent));
    }
}

template<typename FieldT, size_t Exponent>
void MiMC_round_gadget<FieldT, Exponent>::generate_r1cs_witness() const
{
    key.evaluate(this->pb);
    msg.evaluate(this->pb);

    constexpr size_t mask = 1 << (EXPONENT_NUM_BITS - 1);
    const FieldT k_val = this->pb.lc_val(key);
    const FieldT t = this->pb.lc_val(msg) + k_val + round_const;

    // First intermediate variable has value t^2
    size_t exp = Exponent << 1;
    FieldT v = t * t;
    this->pb.val(exponents[0]) = v;

    // Square-and-multiply remaining bits, except final one.
    size_t var_idx = 1;
    for (size_t i = 1; i < EXPONENT_NUM_BITS - 1; ++i) {
        if (exp & mask) {
            // v <- v * t
            v = v * t;
            this->pb.val(exponents[var_idx++]) = v;
        }

        v = v * v;
        this->pb.val(exponents[var_idx++]) = v;
    }

    // v = v * t + add_to_result
    v = v * t;
    if (add_to_result_is_valid) {
        add_to_result.evaluate(this->pb);
        v = v + this->pb.lc_val(add_to_result);
    }
    this->pb.val(result) = v;
}

} // namespace libzeth

#endif // __ZETH_CIRCUITS_MIMC_ROUND_TCC__
