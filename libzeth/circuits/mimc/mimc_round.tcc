// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CIRCUITS_MIMC_ROUND_TCC__
#define __ZETH_CIRCUITS_MIMC_ROUND_TCC__

#include "libzeth/circuits/mimc/mimc_round.hpp"

namespace libzeth
{

template<typename FieldT, size_t Exponent>
MiMC_round_gadget<FieldT, Exponent>::MiMC_round_gadget(
    libsnark::protoboard<FieldT> &pb,
    const libsnark::pb_variable<FieldT> &x,
    const libsnark::pb_variable<FieldT> &k,
    const FieldT &c,
    libsnark::pb_variable<FieldT> &result,
    const bool add_k_to_result,
    const std::string &annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix)
    , _x(x)
    , _k(k)
    , _c(c)
    , _result(result)
    , _add_k_to_result(add_k_to_result)
{
    // Each condition requires an intermediate variable, except the final one,
    // which uses _result (and optionally _k).
    _exponents.resize(NUM_CONDITIONS - 1);
}

template<typename FieldT, size_t Exponent>
void MiMC_round_gadget<FieldT, Exponent>::generate_r1cs_constraints()
{
    // Mask to capture the most significant bit (the "current" bit when
    // iterating from most to least significant).
    constexpr size_t mask = 1 << (EXPONENT_NUM_BITS - 1);
    // t = x + k + c
    libsnark::pb_linear_combination<FieldT> t;
    t.assign(this->pb, _x + _k + _c);

    // For first bit (1 by definition) compute t^2
    size_t exp = Exponent << 1;
    _exponents[0].allocate(this->pb, FMT(this->annotation_prefix, "^2"));
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(t, t, _exponents[0]),
        FMT(this->annotation_prefix, " mul[0]"));

    size_t exp_idx = 1;
    libsnark::pb_variable<FieldT> *last = &_exponents[0];

    // Square-and-multiply based on all bits up to the final (lowest-order) bit.
    for (size_t i = 1; i < EXPONENT_NUM_BITS - 1; ++i) {
        if (exp & mask) {
            // last = last * t
            const size_t new_exp = exp >> (EXPONENT_NUM_BITS - 1);
            _exponents[exp_idx].allocate(
                this->pb, FMT(this->annotation_prefix, "^%zu", new_exp));
            this->pb.add_r1cs_constraint(
                libsnark::r1cs_constraint<FieldT>(
                    t, *last, _exponents[exp_idx]),
                FMT(this->annotation_prefix, " mul[%zu]", exp_idx));
            last = &_exponents[exp_idx];
            ++exp_idx;
        }

        // last = last * last
        const size_t new_exp = 2 * (exp >> (EXPONENT_NUM_BITS - 1));
        _exponents[exp_idx].allocate(
            this->pb, FMT(this->annotation_prefix, "^%zu", new_exp));
        this->pb.add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(
                *last, *last, _exponents[exp_idx]),
            FMT(this->annotation_prefix, " mul[%zu]", exp_idx));
        last = &_exponents[exp_idx];
        ++exp_idx;

        // Net bit
        exp = exp << 1;
    }
    assert(exp_idx == _exponents.size());

    // Final multiply (lowest-order bit is known to be 1):
    //   result = last * t (+ k)
    // such that:
    //   result (- k) = last * t

    if (_add_k_to_result) {
        this->pb.add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(*last, t, _result - _k),
            FMT(this->annotation_prefix, " mul[%zu]", exp_idx));
    } else {
        this->pb.add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(*last, t, _result),
            FMT(this->annotation_prefix, " mul[%zu]", exp_idx));
    }
}

template<typename FieldT, size_t Exponent>
void MiMC_round_gadget<FieldT, Exponent>::generate_r1cs_witness() const
{
    constexpr size_t mask = 1 << (EXPONENT_NUM_BITS - 1);
    const FieldT k_val = this->pb.val(_k);
    const FieldT t = this->pb.val(_x) + k_val + _c;

    // First intermediate variable has valute t^2
    size_t exp = Exponent << 1;
    FieldT v = t * t;
    this->pb.val(_exponents[0]) = v;

    // Square-and-multiply remaining bits, except final one.
    size_t var_idx = 1;
    for (size_t i = 1; i < EXPONENT_NUM_BITS - 1; ++i) {
        if (exp & mask) {
            // v <- v * t
            v = v * t;
            this->pb.val(_exponents[var_idx++]) = v;
        }

        v = v * v;
        this->pb.val(_exponents[var_idx++]) = v;
    }

    // v = v * t (+ k)
    v = v * t;
    if (_add_k_to_result) {
        v = v + k_val;
    }
    this->pb.val(_result) = v;
}

} // namespace libzeth

#endif // __ZETH_CIRCUITS_MIMC_ROUND_TCC__
