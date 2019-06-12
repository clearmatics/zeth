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
        const FieldT& in_C,
        const bool in_add_k_to_result,
        const std::string &annotation_prefix
    ) :
        libsnark::gadget<FieldT>(pb, annotation_prefix),
        x(in_x), k(in_k), C(in_C),
        add_k_to_result(in_add_k_to_result)
    {
      a.allocate(pb, FMT(annotation_prefix, ".a"));
      b.allocate(pb, FMT(annotation_prefix, ".b"));
      c.allocate(pb, FMT(annotation_prefix, ".c"));
      d.allocate(pb, FMT(annotation_prefix, ".d"));
     }

template<typename FieldT>
const libsnark::pb_variable<FieldT>& MiMCe7_round_gadget<FieldT>:: result() const {
        return d;
    }

template<typename FieldT>
void MiMCe7_round_gadget<FieldT>::generate_r1cs_constraints() {
        libsnark::linear_combination<FieldT> t = x + k + C; // define t as the value to exponentiate

        this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(t, t, a), ".a = t*t"); // Add constrain a = t^2
        this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(a, a, b), ".b = a*a"); // Add constrain b = a^2 = t^4
        this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(a, b, c), ".c = a*b"); // Add constrain c = a*b = t^6

        if( add_k_to_result )
        {
            this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(t, c, d - k), ".out = (c*t) + k"); // Add constrain d = t*c + k = t^7 + k (key included)
        }
        else {
            this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(t, c, d), ".out = c*t"); // Add constrain d = t*c = t^7
        }
    }

template<typename FieldT>
void  MiMCe7_round_gadget<FieldT>::generate_r1cs_witness() const {
        const FieldT val_k = this->pb.val(k); // fill key value
        const FieldT t = this->pb.val(x) + val_k + C; // fill t value

        //intermediary values
        const FieldT val_a = t * t;
        this->pb.val(a) = val_a; //fill t^2

        const FieldT val_b = val_a * val_a;
        this->pb.val(b) = val_b;  //fill t^4

        const FieldT val_c = val_a * val_b;
        this->pb.val(c) = val_c;  //fill t^6

        const FieldT result = (val_c * t) + (add_k_to_result ? val_k : FieldT::zero()); //fill t^7 or t^7 + k
        this->pb.val(d) = result;
    }
}

#endif // __ZETH_MIMC_ROUND_TCC
