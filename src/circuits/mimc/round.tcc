// DISCLAIMER:
// Content taken and adapted from:
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/mimc.hpp

#ifndef __ZETH_MIMC_ROUND_TCC__
#define __ZETH_MIMC_ROUND_TCC__

namespace libzeth {

template<typename FieldT>
MiMCe7_round_gadget<FieldT>::MiMCe7_round_gadget(
    libsnark::protoboard<FieldT>& pb,
    const libsnark::pb_variable<FieldT> x,
    const libsnark::pb_variable<FieldT> k,
    const FieldT& c,
    const bool add_k_to_result,
    const std::string &annotation_prefix
) :
    libsnark::gadget<FieldT>(pb, annotation_prefix),
    x(x),
    k(k),
    c(c),
    add_k_to_result(add_k_to_result)
{
    // Allocate the intermediary variables
    t2.allocate(pb, FMT(annotation_prefix, ".t2"));
    t4.allocate(pb, FMT(annotation_prefix, ".t4"));
    t6.allocate(pb, FMT(annotation_prefix, ".t6"));
    t7.allocate(pb, FMT(annotation_prefix, ".out"));
};

template<typename FieldT>
void MiMCe7_round_gadget<FieldT>::generate_r1cs_constraints() {
    // First define the temporary variable t as a linear combination of x, k and c
    libsnark::linear_combination<FieldT> t = x + k + c;

    // Define a common annotation for round constraints
    const std::string annotation_constraint = this->annotation_prefix + std::string(".round constraint");

    // Constrain the intermediary variables t2 t4 and t6
    //
    // Add contraint `a = t^2`
    this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(t, t, t2), FMT(annotation_constraint, ".t2"));
    // Add contraint `b = a^2 = t^4`
    this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(t2, t2, t4), FMT(annotation_constraint, ".t4"));
    // Add contraint `c = a*b = t^6`
    this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(t2, t4, t6), FMT(annotation_constraint, ".t6"));

    // Constrain t7 depending on the value of `add_k_to_result`
    if(add_k_to_result) {
        // Add constraint d = t*c + k = t^7 + k (key included)
        this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(t, t6, t7 - k), FMT(annotation_constraint,".out + k"));
    } else {
        // Add constraint d = t*c = t^7
        this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(t, t6, t7), FMT(annotation_constraint,".out"));
    }
};

template<typename FieldT>
void  MiMCe7_round_gadget<FieldT>::generate_r1cs_witness() const {
    // First, fill the values of key and t
    const FieldT val_k = this->pb.val(k);
    const FieldT t = this->pb.val(x) + val_k + c;

    // Compute the intermediary values and fill intermediary variables with them
    const FieldT val_t2 = t * t;
    this->pb.val(t2) = val_t2;

    const FieldT val_t4 = val_t2 * val_t2;
    this->pb.val(t4) = val_t4;

    const FieldT val_t6 = val_t2 * val_t4;
    this->pb.val(t6) = val_t6;

    const FieldT result = (val_t6 * t) + (add_k_to_result ? val_k : FieldT::zero());
    this->pb.val(t7) = result;
};

template<typename FieldT>
const libsnark::pb_variable<FieldT>& MiMCe7_round_gadget<FieldT>:: result() const {
    return t7;
};

} // libzeth

#endif // __ZETH_MIMC_ROUND_TCC__
