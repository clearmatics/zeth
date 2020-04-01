// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CIRCUITS_BINARY_OPERATION_TCC__
#define __ZETH_CIRCUITS_BINARY_OPERATION_TCC__

#include "libzeth/circuits/circuits-utils.hpp"
#include "libzeth/types/bits.hpp"

#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>

namespace libzeth
{

template<typename FieldT>
xor_gadget<FieldT>::xor_gadget(
    libsnark::protoboard<FieldT> &pb,
    const libsnark::pb_variable_array<FieldT> a,
    const libsnark::pb_variable_array<FieldT> b,
    libsnark::pb_variable_array<FieldT> res,
    const std::string &annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix), a(a), b(b), res(res)
{
    assert(a.size() == b.size());
    assert(b.size() == res.size());
};

template<typename FieldT> void xor_gadget<FieldT>::generate_r1cs_constraints()
{
    // Set the constraints (#constraints = length of bit string)
    for (size_t i = 0; i < a.size(); i++) {
        // res = a XOR b <=> (2.a) * b = a + b - res
        this->pb.add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(
                2 * a[i], b[i], a[i] + b[i] - res[i]),
            FMT(this->annotation_prefix, " xored_bits_%zu", i));
    }
};

template<typename FieldT> void xor_gadget<FieldT>::generate_r1cs_witness()
{
    for (size_t i = 0; i < a.size(); i++) {
        if (this->pb.val(a[i]) == FieldT("1") &&
            this->pb.val(b[i]) == FieldT("1")) {
            this->pb.val(res[i]) = FieldT("0");
        } else {
            this->pb.val(res[i]) = this->pb.val(a[i]) + this->pb.val(b[i]);
        }
    }
};

template<typename FieldT>
xor_constant_gadget<FieldT>::xor_constant_gadget(
    libsnark::protoboard<FieldT> &pb,
    const libsnark::pb_variable_array<FieldT> a,
    const libsnark::pb_variable_array<FieldT> b,
    std::vector<FieldT> c,
    libsnark::pb_variable_array<FieldT> res,
    const std::string &annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix)
    , a(a)
    , b(b)
    , c(c)
    , res(res)
{
    assert(a.size() == b.size());
    assert(b.size() == c.size());
    assert(c.size() == res.size());
};

template<typename FieldT>
void xor_constant_gadget<FieldT>::generate_r1cs_constraints()
{
    // Set the constraints (#constraints = length of bit string)
    //
    // We know that: res = a XOR b <=> (2.a) * b = a + b - res
    // we can write: res = a + b - 2ab
    //
    // Hence, res2 = a XOR b XOR c = (a XOR b) XOR c <=> res XOR c
    // Thus: res2 = res XOR c is constrainted as:
    //   2(res) * c = res + c - res2
    // which leads to:
    //   2(a + b - 2ab) * c = a + b - 2ab + c - res2
    // => res2 = a + b - 2ab + c - 2ac - 2bc + 4abc
    // => res2 - c = b * (4ac - 2a) + a + b - 2ac - 2bc
    // => res2 - c = b * (4ac - 2a) + a * (1 - 2c) + b * (1 - 2c)
    // => res2 - c - a * (1 - 2c) - b * (1 - 2c) = b * (4ac - 2a)
    // and b * (4ac - 2a) = b * [2 * (2c - 1) *a] = b * [-2 * (1 - 2c) *a]
    for (size_t i = 0; i < a.size(); i++) {
        this->pb.add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(
                -FieldT("2") * (FieldT("1") - FieldT("2") * c[i]) * a[i],
                b[i],
                res[i] - c[i] - a[i] * (FieldT("1") - FieldT("2") * c[i]) -
                    b[i] * (FieldT("1") - FieldT("2") * c[i])),
            FMT(this->annotation_prefix, " rotated_xored_bits_%zu", i));
    }
};

template<typename FieldT>
void xor_constant_gadget<FieldT>::generate_r1cs_witness()
{
    for (size_t i = 0; i < a.size(); i++) {
        if ((this->pb.val(a[i]) == FieldT("0") &&
             this->pb.val(b[i]) == FieldT("0") && c[i] == FieldT("0")) ||
            (this->pb.val(a[i]) == FieldT("1") &&
             this->pb.val(b[i]) == FieldT("0") && c[i] == FieldT("1")) ||
            (this->pb.val(a[i]) == FieldT("0") &&
             this->pb.val(b[i]) == FieldT("1") && c[i] == FieldT("1")) ||
            (this->pb.val(a[i]) == FieldT("1") &&
             this->pb.val(b[i]) == FieldT("1") && c[i] == FieldT("0"))) {
            this->pb.val(res[i]) = FieldT("0");
        } else {
            this->pb.val(res[i]) = FieldT("1");
        }
    }
};

template<typename FieldT>
xor_rot_gadget<FieldT>::xor_rot_gadget(
    libsnark::protoboard<FieldT> &pb,
    const libsnark::pb_variable_array<FieldT> a,
    const libsnark::pb_variable_array<FieldT> b,
    const size_t &shift,
    libsnark::pb_variable_array<FieldT> res,
    const std::string &annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix)
    , a(a)
    , b(b)
    , shift(shift)
    , res(res)
{
    assert(a.size() == b.size());
    assert(b.size() == res.size());
};

template<typename FieldT>
void xor_rot_gadget<FieldT>::generate_r1cs_constraints()
{
    // Set the constraints (#constraints = length of bit string)
    for (size_t i = 0; i < a.size(); i++) {
        this->pb.add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(
                2 * a[i], b[i], a[i] + b[i] - res[(i + shift) % a.size()]),
            FMT(this->annotation_prefix, " rotated_xored_bits_%zu", i));
    }
};

template<typename FieldT> void xor_rot_gadget<FieldT>::generate_r1cs_witness()
{
    // Set the witness (#values = length of bit string)
    for (size_t i = 0; i < a.size(); i++) {
        if (this->pb.val(a[i]) == FieldT("1") &&
            this->pb.val(b[i]) == FieldT("1")) {
            this->pb.val(res[(i + shift) % a.size()]) = FieldT("0");
        } else {
            this->pb.val(res[(i + shift) % a.size()]) =
                this->pb.val(a[i]) + this->pb.val(b[i]);
        }
    }
};

template<typename FieldT>
double_bit32_sum_eq_gadget<FieldT>::double_bit32_sum_eq_gadget(
    libsnark::protoboard<FieldT> &pb,
    libsnark::pb_variable_array<FieldT> a,
    libsnark::pb_variable_array<FieldT> b,
    libsnark::pb_variable_array<FieldT> res,
    const std::string &annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix), a(a), b(b), res(res)
{
    assert(a.size() == 32);
    assert(a.size() == b.size());
    assert(a.size() == res.size());
};

template<typename FieldT>
void double_bit32_sum_eq_gadget<FieldT>::generate_r1cs_constraints(
    bool enforce_boolean)
{
    // We want to check that a + b = c mod 2^32
    // A way to do this is to follow the proposed implementation
    // section A.3.7 of the Zcash protocol spec:
    // https://github.com/zcash/zips/blob/master/protocol/protocol.pdf
    //
    // Below, we propose an alternative way to constraint the result to
    // be a boolean string and to be the valid sum of a and b.
    //
    // Let a and b be the input bit string of length 32 bits (uint32)
    // Let res be the claimed result of a + b of length 33 bits (an additional
    // bit account for the potential carry of the addition of a and b)
    //
    // The goal here is to:
    //  1. Constraint the 33bits of res to make sure it is a bit string of
    // length 33bits
    //   $\forall i \in {0, 32} c_i*(c_i-1) = 0$ (33 constraints)
    //  2. Constraint a,b and res to make sure that a + b = res % 2^32
    //   $\sum_{i=0}^{31} (a_i + b_i) * 2^i = \sum_{i=0}^{32} c_i * 2^i$
    //
    // The first set of constraints can be re-written as:
    // 1.1 $\forall i \in {0, 31} c_i*(c_i-1) = 0$ (32 constraints)
    // 1.2 $c_{32}*(c_{32}-1) = 0$ => $2^{32}c_{32}*(2^{32}c_{32}-2^{32}) = 0$
    // (multiply by $2^{{32}^2}$)
    //
    // and 2. can be rewritten as:
    //   $\sum_{i=0}^{31} (a_i + b_i - c_i) * 2^i = c_{32} * 2^{32}$
    //
    // Now, we can replace $2^{32}c_{32}$ in 1.2 by
    // $\sum_{i=0}^{31} (a_i + b_i - c_i) * 2^i$
    // and we obtain:
    // 1.2' $[\sum_{i=0}^{31} (a_i + b_i - c_i) * 2^i] *
    //       ([\sum_{i=0}^{31} (a_i + b_i - c_i) * 2^i] - 2^{32}) = 0$
    //
    // Hence, we finally obtain the following constraint system of 33
    // constraints:
    // 1. $\forall i \in {0, 31} c_i*(c_i-1) = 0$ (32 constraints)
    // 2. $[\sum_{i=0}^{31} (a_i + b_i - c_i) * 2^i] *
    //    ([\sum_{i=0}^{31} (a_i + b_i - c_i) * 2^i] - 2^{32}) = 0$
    // (1 constraint)

    // 1. Implement the first set of constraints:
    // $\forall i \in {0, 31} c_i*(c_i-1) = 0$
    if (enforce_boolean) {
        for (size_t i = 0; i < 32; i++) {
            libsnark::generate_boolean_r1cs_constraint<FieldT>(
                this->pb, res[i], FMT(this->annotation_prefix, " res[%zu]", i));
        }
    }

    libsnark::linear_combination<FieldT> left_side =
        packed_addition(a) + packed_addition(b);

    // 2. Final constraint:
    // $[\sum_{i=0}^{31} (a_i + b_i - c_i) * 2^i] *
    //  ([\sum_{i=0}^{31} (a_i + b_i - c_i) * 2^i] - 2^{32}) = 0$
    // The only way to satisfy this constraint is to have either:
    // a. left_side = res + 0 * 2*32, or
    // b. left_side = res + 1 * 2^32
    // This constraint leverages the fact that the sum of two N-bit numbers
    // can at most lead to a (N+1)-bit number.
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(
            (left_side - packed_addition(res)),
            (left_side - packed_addition(res) - pow(2, 32)),
            0),
        FMT(this->annotation_prefix, " sum_equal_sum_constraint"));
};

template<typename FieldT>
void double_bit32_sum_eq_gadget<FieldT>::generate_r1cs_witness()
{
    bits32 a_bits32;
    bits32 b_bits32;
    for (size_t i = 0; i < 32; i++) {
        a_bits32[i] = a.get_bits(this->pb)[i];
        b_bits32[i] = b.get_bits(this->pb)[i];
    }

    bits32 left_side_acc = binary_addition<32>(a_bits32, b_bits32, false);
    res.fill_with_bits(this->pb, get_vector_from_bits32(left_side_acc));
};

} // namespace libzeth

#endif // __ZETH_CIRCUITS_BINARY_OPERATION_TCC__