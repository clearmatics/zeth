// DISCLAIMER:
// Content taken and adapted from:
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/mimc.hpp

#ifndef __ZETH_MIMC_ROUND_TCC__
#define __ZETH_MIMC_ROUND_TCC__

namespace libzeth {

template<typename FieldT>
MiMCe7_round_gadget<FieldT>::MiMCe7_round_gadget(
        libsnark::protoboard<FieldT>& pb,
        const libsnark::pb_variable<FieldT> in_x,
        const libsnark::pb_variable<FieldT> in_k,
        const FieldT& in_constant,
        const bool in_add_k_to_result,
        const std::string &annotation_prefix
    ) :
        libsnark::gadget<FieldT>(pb, annotation_prefix),
        x(in_x), k(in_k), c(in_constant),
        add_k_to_result(in_add_k_to_result)
    {
      t2.allocate(pb, FMT(annotation_prefix, ".a"));
      t4.allocate(pb, FMT(annotation_prefix, ".b"));
      t6.allocate(pb, FMT(annotation_prefix, ".c"));
      t7.allocate(pb, FMT(annotation_prefix, ".d"));
     }

template<typename FieldT>
const libsnark::pb_variable<FieldT>& MiMCe7_round_gadget<FieldT>:: result() const {
        return t7;
    }

template<typename FieldT>
void MiMCe7_round_gadget<FieldT>::generate_r1cs_constraints() {
        libsnark::linear_combination<FieldT> t = x + k + c; // define `t` as the variable to exponentiate

        this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(t, t, t2), ".a = t*t"); // Add constraint `a = t^2`
        this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(t2, t2, t4), ".b = a*a"); // Add constraint `b = a^2 = t^4`
        this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(t2, t4, t6), ".c = a*b"); // Add constraint `c = a*b = t^6`

        if( add_k_to_result )
        {
            this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(t, t6, t7 - k), ".out = (c*t) + k"); // Add constraint d = t*c + k = t^7 + k (key included)
        }
        else {
            this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(t, t6, t7), ".out = c*t"); // Add constraint d = t*c = t^7
        }
    }

template<typename FieldT>
void  MiMCe7_round_gadget<FieldT>::generate_r1cs_witness() const {
        // fill key and t value
        const FieldT val_k = this->pb.val(k);
        const FieldT t = this->pb.val(x) + val_k + c;

        //fill intermediary values
        const FieldT val_a = t * t;
        this->pb.val(t2) = val_a;

        const FieldT val_b = val_a * val_a;
        this->pb.val(t4) = val_b;

        const FieldT val_c = val_a * val_b;
        this->pb.val(t6) = val_c;

        const FieldT result = (val_c * t) + (add_k_to_result ? val_k : FieldT::zero());
        this->pb.val(t7) = result;
    }
}

#endif // __ZETH_MIMC_ROUND_TCC
