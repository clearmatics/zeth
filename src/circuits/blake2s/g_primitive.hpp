#ifndef __ZETH_CIRCUITS_G_PRIMITIVE_HPP__
#define __ZETH_CIRCUITS_G_PRIMITIVE_HPP__

#include "circuits/binary_operation.hpp"
#include "circuits/circuits-util.hpp"
#include "types/bits.hpp"

#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>

namespace libzeth
{

/// g_primitive is the gadget implementing the mixing function G
/// used in Blake2s. See: https://tools.ietf.org/html/rfc7693#section-3.1
template<typename FieldT> class g_primitive : public libsnark::gadget<FieldT>
{
private:
    // See: Section 2.1 https://tools.ietf.org/html/rfc7693
    static const int rotation_constant_r1 = 16;
    static const int rotation_constant_r2 = 12;
    static const int rotation_constant_r3 = 8;
    static const int rotation_constant_r4 = 7;

    libsnark::pb_variable_array<FieldT> a1;
    libsnark::pb_variable_array<FieldT> a1_temp;
    libsnark::pb_variable_array<FieldT> a2_temp;
    libsnark::pb_variable_array<FieldT> b1;
    libsnark::pb_variable_array<FieldT> c1;
    libsnark::pb_variable_array<FieldT> d1;

    libsnark::pb_variable_array<FieldT> a2;
    libsnark::pb_variable_array<FieldT> b2;
    libsnark::pb_variable_array<FieldT> c2;
    libsnark::pb_variable_array<FieldT> d2;

    std::shared_ptr<xor_rot_gadget<FieldT>> d1_xor_gadget;
    std::shared_ptr<xor_rot_gadget<FieldT>> b1_xor_gadget;
    std::shared_ptr<xor_rot_gadget<FieldT>> d2_xor_gadget;
    std::shared_ptr<xor_rot_gadget<FieldT>> b2_xor_gadget;
    std::shared_ptr<double_bit32_sum_eq_gadget<FieldT>> a1_1_sum_gadget;
    std::shared_ptr<double_bit32_sum_eq_gadget<FieldT>> a1_2_sum_gadget;
    std::shared_ptr<double_bit32_sum_eq_gadget<FieldT>> c1_sum_gadget;
    std::shared_ptr<double_bit32_sum_eq_gadget<FieldT>> a2_1_sum_gadget;
    std::shared_ptr<double_bit32_sum_eq_gadget<FieldT>> a2_2_sum_gadget;
    std::shared_ptr<double_bit32_sum_eq_gadget<FieldT>> c2_sum_gadget;

public:
    g_primitive(
        libsnark::protoboard<FieldT> &pb,
        libsnark::pb_variable_array<FieldT> a,
        libsnark::pb_variable_array<FieldT> b,
        libsnark::pb_variable_array<FieldT> c,
        libsnark::pb_variable_array<FieldT> d,
        libsnark::pb_variable_array<FieldT> x,
        libsnark::pb_variable_array<FieldT> y,
        libsnark::pb_variable_array<FieldT> a2,
        libsnark::pb_variable_array<FieldT> b2,
        libsnark::pb_variable_array<FieldT> c2,
        libsnark::pb_variable_array<FieldT> d2,
        const std::string &annotation_prefix = "g_primitive_gadget");

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

} // namespace libzeth
#include "g_primitive.tcc"

#endif // __ZETH_CIRCUITS_G_PRIMITIVE_HPP__