#ifndef __ZETH_SIMPLE_GADGETS_TCC__
#define __ZETH_SIMPLE_GADGETS_TCC__

#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/gadgetlib1/gadget.hpp>

#include "circuits/circuits-util.hpp"
#include "types/bits.hpp"

namespace libzeth {

template<typename FieldT>
xor_gadget<FieldT>::xor_gadget(
    libsnark::protoboard<FieldT>& pb,
    const libsnark::pb_variable_array<FieldT> a,
    const libsnark::pb_variable_array<FieldT> b,
    libsnark::pb_variable_array<FieldT> res,
    const std::string &annotation_prefix
):
    libsnark::gadget<FieldT>(pb, annotation_prefix),
    a(a), b(b), res(res)
{
    assert(a.size() == b.size());
    assert(b.size() == res.size());
};
        
template<typename FieldT>
void xor_gadget<FieldT>::generate_r1cs_constraints() {
    // 32 constraints
    for (size_t i = 0; i < a.size(); i++) {
        this->pb.add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(
                -2*a[i],
                b[i],
                res[i] - a[i] - b[i]
            ),
            FMT(this->annotation_prefix, " rotated_xored_bits_%zu", i)
        );
    }
};

template<typename FieldT>
void xor_gadget<FieldT>::generate_r1cs_witness(){
    for (size_t i = 0; i < a.size(); i++) {
        if ( this->pb.val(a[i]) == FieldT("1") && this->pb.val(b[i]) == FieldT("1")){
            this->pb.val(res[i]) = FieldT("0");
        } else {
            this->pb.val(res[i]) = this->pb.val(a[i]) + this->pb.val(b[i]);
        }
    }
};


template<typename FieldT>
xor_constant_gadget<FieldT>::xor_constant_gadget(
    libsnark::protoboard<FieldT>& pb,
    const libsnark::pb_variable_array<FieldT> a,
    const libsnark::pb_variable_array<FieldT> b,
    std::vector<FieldT> c,
    libsnark::pb_variable_array<FieldT> res,
    const std::string &annotation_prefix
):
    libsnark::gadget<FieldT>(pb, annotation_prefix),
    a(a), b(b), c(c), res(res)
{
    assert(a.size() == b.size());
    assert(b.size() == c.size());
    assert(c.size() == res.size());
};
        
template<typename FieldT>
void xor_constant_gadget<FieldT>::generate_r1cs_constraints() {
    // 32 constraints
    for (size_t i = 0; i < a.size(); i++) {
        this->pb.add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(
                -FieldT("2")*(FieldT("1")-FieldT("2")*c[i])*a[i],
                b[i],
                res[i] -c[i] - a[i]*(FieldT("1")-FieldT("2")*c[i]) - b[i]*(FieldT("1")-FieldT("2")*c[i])
            ),
            FMT(this->annotation_prefix, " rotated_xored_bits_%zu", i)
        );
    }
};

template<typename FieldT>
void xor_constant_gadget<FieldT>::generate_r1cs_witness(){
    for (size_t i = 0; i < a.size(); i++) {
        if (
            (this->pb.val(a[i]) == FieldT("0") && this->pb.val(b[i]) == FieldT("0") && c[i] == FieldT("0")) ||
            (this->pb.val(a[i]) == FieldT("1") && this->pb.val(b[i]) == FieldT("0") && c[i] == FieldT("1")) ||
            (this->pb.val(a[i]) == FieldT("0") && this->pb.val(b[i]) == FieldT("1") && c[i] == FieldT("1")) ||
            (this->pb.val(a[i]) == FieldT("1") && this->pb.val(b[i]) == FieldT("1") && c[i] == FieldT("0")) 
        ){
            this->pb.val(res[i]) = FieldT("0");
        } else {
            this->pb.val(res[i]) = FieldT("1");
        }
    }
};

template<typename FieldT>
xor_rot_gadget<FieldT>::xor_rot_gadget(
    libsnark::protoboard<FieldT>& pb,
    const libsnark::pb_variable_array<FieldT> a,
    const libsnark::pb_variable_array<FieldT> b,
    const size_t& shift,
    libsnark::pb_variable_array<FieldT> res,
    const std::string &annotation_prefix
):
    libsnark::gadget<FieldT>(pb, annotation_prefix),
    a(a), b(b), shift(shift), res(res)
{
    assert(a.size() == b.size());
    assert(b.size() == res.size());
};
        
template<typename FieldT>
void xor_rot_gadget<FieldT>::generate_r1cs_constraints() {
    // 32 constraints
    for (size_t i = 0; i < a.size(); i++) {
        this->pb.add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(
                -2*a[i],
                b[i],
                res[(i + shift) % a.size()] - a[i] - b[i]
            ),
            FMT(this->annotation_prefix, " rotated_xored_bits_%zu", i)
        );
    }
};

template<typename FieldT>
void xor_rot_gadget<FieldT>::generate_r1cs_witness(){
    // 32 constraints
    for (size_t i = 0; i < a.size(); i++) {
        if ( this->pb.val(a[i]) == FieldT("1") && this->pb.val(b[i]) == FieldT("1")){
            this->pb.val(res[(i + shift) % a.size()]) = FieldT("0");
        } else {
            this->pb.val(res[(i + shift) % a.size()]) = this->pb.val(a[i]) + this->pb.val(b[i]);
        }
    }
};

template<typename FieldT>
double_bit32_sum_eq_gadget<FieldT>::double_bit32_sum_eq_gadget(
    libsnark::protoboard<FieldT> &pb,
    libsnark::pb_variable_array<FieldT> a,
    libsnark::pb_variable_array<FieldT> b,
    libsnark::pb_variable_array<FieldT> res,
    const std::string &annotation_prefix
):
    libsnark::gadget<FieldT>(pb, annotation_prefix),
    a(a), b(b), res(res)
{
    assert(a.size() == 32);
    assert(a.size() == b.size());
    assert(a.size() == res.size());
};

template<typename FieldT>
void double_bit32_sum_eq_gadget<FieldT>::generate_r1cs_constraints(bool enforce_boolean) {
    // 33 constraints (32 +1)
    if (enforce_boolean){
        for (size_t i = 0; i < 32; i++) {
            libsnark::generate_boolean_r1cs_constraint<FieldT>(
                this->pb,
                res[i],
                FMT(this->annotation_prefix, " res[%zu]", i)
            );
        }
    }    

    libsnark::linear_combination<FieldT> left_side = packed_addition(a) + packed_addition(b);

    this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(
        (left_side - packed_addition(res)),
        (left_side - packed_addition(res) - pow(2,32)),
        0
        ),
        FMT(this->annotation_prefix, " sum_equal_sum_constraint")
    );
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
    
    bits32 left_side_acc = binaryAdditionNoCarry<32>(a_bits32, b_bits32);
    res.fill_with_bits(
        this->pb,
        get_vector_from_bits32(left_side_acc)
    );
};

} // libzeth

#endif // __ZZETH_SIMPLE_GADGETS_TCC__