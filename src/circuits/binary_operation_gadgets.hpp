#ifndef __ZETH_BINARY_OPERATION_GADGETS_HPP__
#define __ZETH_BINARY_OPERATION_GADGETS_HPP__

#include "circuits/circuits-util.hpp"
#include "math.h"
#include "types/bits.hpp"

#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>

namespace libzeth
{

/// xor_gadget computes res = a XOR b
template<typename FieldT> class xor_gadget : public libsnark::gadget<FieldT>
{

private:
    const libsnark::pb_variable_array<FieldT> a;
    const libsnark::pb_variable_array<FieldT> b;

public:
    libsnark::pb_variable_array<FieldT> res;

    xor_gadget(
        libsnark::protoboard<FieldT> &pb,
        const libsnark::pb_variable_array<FieldT> a,
        const libsnark::pb_variable_array<FieldT> b,
        libsnark::pb_variable_array<FieldT> res,
        const std::string &annotation_prefix = "xor_gadget");

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

/// xor_constant_gadget computes res = a XOR b XOR c with c constant
template<typename FieldT>
class xor_constant_gadget : public libsnark::gadget<FieldT>
{

private:
    const libsnark::pb_variable_array<FieldT> a;
    const libsnark::pb_variable_array<FieldT> b;
    const std::vector<FieldT> c;

public:
    libsnark::pb_variable_array<FieldT> res;

    xor_constant_gadget(
        libsnark::protoboard<FieldT> &pb,
        const libsnark::pb_variable_array<FieldT> a,
        const libsnark::pb_variable_array<FieldT> b,
        const std::vector<FieldT> c,
        libsnark::pb_variable_array<FieldT> res,
        const std::string &annotation_prefix = "xor_constant_gadget");

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

/// xor_rot_gadget computes a XOR b and rotate it by shift
template<typename FieldT> class xor_rot_gadget : public libsnark::gadget<FieldT>
{

private:
    const libsnark::pb_variable_array<FieldT> a;
    const libsnark::pb_variable_array<FieldT> b;
    const size_t shift;

public:
    libsnark::pb_variable_array<FieldT> res;

    xor_rot_gadget(
        libsnark::protoboard<FieldT> &pb,
        const libsnark::pb_variable_array<FieldT> a,
        const libsnark::pb_variable_array<FieldT> b,
        const size_t &shift,
        libsnark::pb_variable_array<FieldT> res,
        const std::string &annotation_prefix = "xor_rot_gadget");

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

/// double_bit32_sum_eq_gadget checks that res = a + b % 2**32
/// with a, b and res being 32-bit long arrays
template<typename FieldT>
class double_bit32_sum_eq_gadget : public libsnark::gadget<FieldT>
{

private:
    libsnark::pb_variable_array<FieldT> a;
    libsnark::pb_variable_array<FieldT> b;

public:
    libsnark::pb_variable_array<FieldT> res;

    double_bit32_sum_eq_gadget(
        libsnark::protoboard<FieldT> &pb,
        libsnark::pb_variable_array<FieldT> a,
        libsnark::pb_variable_array<FieldT> b,
        libsnark::pb_variable_array<FieldT> res,
        const std::string &annotation_prefix = "double_bit32_sum_eq_gadget");

    void generate_r1cs_constraints(bool enforce_boolean = true);
    void generate_r1cs_witness();
};

} // namespace libzeth
#include "binary_operation_gadgets.tcc"

#endif // __ZETH_BINARY_OPERATION_GADGETS_HPP__