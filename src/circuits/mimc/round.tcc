// DISCLAIMER:
// Content taken and adapted from:
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/mimc.hpp

#ifndef __ZETH_MIMC_ROUND_TCC__
#define __ZETH_MIMC_ROUND_TCC__

namespace libzeth {

MiMCe7_round_gadget::MiMCe7_round_gadget(
        ProtoboardT& pb,
        const VariableT in_x,
        const VariableT in_k,
        const FieldT& in_C,
        const bool in_add_k_to_result,
        const std::string &annotation_prefix
    ) :
        GadgetT(pb, annotation_prefix),
        x(in_x), k(in_k), C(in_C),
        add_k_to_result(in_add_k_to_result),
        a(make_variable(pb, FMT(annotation_prefix, ".a"))),
        b(make_variable(pb, FMT(annotation_prefix, ".b"))),
        c(make_variable(pb, FMT(annotation_prefix, ".c"))),
        d(make_variable(pb, FMT(annotation_prefix, ".d")))
    { }

const VariableT& MiMCe7_round_gadget:: result() const
    {
        return d;
    }

void MiMCe7_round_gadget::generate_r1cs_constraints()
    {
        auto t = x + k + C;
        this->pb.add_r1cs_constraint(ConstraintT(t, t, a), ".a = t*t"); // t^2
        this->pb.add_r1cs_constraint(ConstraintT(a, a, b), ".b = a*a"); // t^4
        this->pb.add_r1cs_constraint(ConstraintT(a, b, c), ".c = a*b"); // t^6

        if( add_k_to_result )
        {
            this->pb.add_r1cs_constraint(ConstraintT(t, c, d - k), ".out = (c*t) + k"); // t^7
        }
        else {
            this->pb.add_r1cs_constraint(ConstraintT(t, c, d), ".out = c*t"); // t^7
        }
    }

void  MiMCe7_round_gadget::generate_r1cs_witness() const
    {
        const FieldT val_k = this->pb.val(k);
        const FieldT t = this->pb.val(x) + val_k + C;

        const FieldT val_a = t * t;
        this->pb.val(a) = val_a;

        const FieldT val_b = val_a * val_a;
        this->pb.val(b) = val_b;

        const FieldT val_c = val_a * val_b;
        this->pb.val(c) = val_c;

        const FieldT result = (val_c * t) + (add_k_to_result ? val_k : FieldT::zero());
        this->pb.val(d) = result;
    }
}

#endif // __ZETH_MIMC_ROUND_TCC
