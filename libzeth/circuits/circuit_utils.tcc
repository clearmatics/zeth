// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CIRCUITS_CIRCUITS_UTILS_TCC__
#define __ZETH_CIRCUITS_CIRCUITS_UTILS_TCC__

#include <libsnark/gadgetlib1/pb_variable.hpp>
#include <vector>

namespace libzeth
{

// This define directive is useless/redundant, as ONE is defined here:
// libsnark/gadgetlib1/pb_variable.hpp#74
#ifdef ONE
#undef ONE
#endif
#define ONE libsnark::pb_variable<FieldT>(0)
//
// We know that a pb_variable takes an index in the constructor:
// See: libsnark/gadgetlib1/pb_variable.hpp#29
// Then the pb_variable can be allocated on the protoboard
// See here for the allocation function: libsnark/gadgetlib1/pb_variable.tcc#19
// This function calls the allocation function of the protoboard:
// libsnark/gadgetlib1/protoboard.tcc#38 This function basically allocates the
// variable on the protoboard at the index defined by the variable
// "next_free_var". It then returns the index the variable was allocated at,
// and, we can see in libsnark/gadgetlib1/pb_variable.tcc#19 that the index of
// the variable is given by the index where the variable was allocated on the
// protoboard. MOREOVER, we see in: libsnark/gadgetlib1/protoboard.tcc#19 (the
// constructor of the protoboard) that "next_free_var = 1;" to account for
// constant 1 term. Thus, the variable at index 0 on the protoboard is the
// constant_term variable, which value is FieldT::one() (which basically is the
// multiplicative identity of the field FieldT) Thus we are safe here. The ONE
// is well equal to the value FieldT::one()

// Pack input binary strings into F_r and add the resulting field elements
// together
template<typename FieldT>
libsnark::linear_combination<FieldT> packed_addition(
    const libsnark::pb_variable_array<FieldT> &inputs)
{
    // We use `inputs.rbegin(), inputs.rend()` otherwise the resulting linear
    // combination is built by interpreting our bit string as little endian.
    // Thus here, we make sure our binary string is interpreted correctly.
    return libsnark::pb_packing_sum<FieldT>(
        libsnark::pb_variable_array<FieldT>(inputs.rbegin(), inputs.rend()));
};

// Takes a vector of boolean values, and convert this vector of boolean values
// into a vector of FieldT::zero() and FieldT:one()
template<typename FieldT>
libsnark::pb_variable_array<FieldT> variable_array_from_bit_vector(
    const std::vector<bool> &bits, const libsnark::pb_variable<FieldT> &ZERO)
{
    libsnark::pb_variable_array<FieldT> acc;
    acc.reserve(bits.size());
    for (bool bit : bits) {
        acc.emplace_back(bit ? ONE : ZERO);
    }

    return acc;
};

} // namespace libzeth

#endif // __ZETH_CIRCUITS_CIRCUITS_UTILS_TCC__
