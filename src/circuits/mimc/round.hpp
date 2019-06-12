// DISCLAIMER:
// Content taken and adapted from:
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/mimc.hpp

#ifndef __ZETH_MIMC_ROUND_HPP__
#define __ZETH_MIMC_ROUND_HPP__

#include "snarks_alias.hpp"
#include "circuits/circuits-util.hpp"

namespace libzeth {
 /*
  * MiMCe7_round_gadget enforces correct computation of a MiMC permutation round with exponent 7.
  * In MiMC permutation last round differs from the other since the key is added again, so we will use the boolean variable add_k_to_result to manage this case.
  */
template<typename FieldT>
class MiMCe7_round_gadget : public libsnark::gadget<FieldT> {
public:
    const libsnark::pb_variable<FieldT> x;  // round message
    const libsnark::pb_variable<FieldT> k;  // round key
    const FieldT C; // round constant
    const bool add_k_to_result; // variable to add the key after the round: this depend on the fact that in MiMC permutation the key is added at the end of the last round
    libsnark::pb_variable<FieldT> a;  // constraint t^2 variable
    libsnark::pb_variable<FieldT> b;  // constraint t^4 variable
    libsnark::pb_variable<FieldT> c;  // constraint t^6 variable
    libsnark::pb_variable<FieldT> d;  // constraint t^7 variable

public:
    MiMCe7_round_gadget(
        libsnark::protoboard<FieldT>& pb,
        const libsnark::pb_variable<FieldT> in_x,
        const libsnark::pb_variable<FieldT> in_k,
        const FieldT& in_C,
        const bool in_add_k_to_result,
        const std::string &annotation_prefix
    );

    const libsnark::pb_variable<FieldT>& result() const;  // return output variable
    void generate_r1cs_constraints();
    void generate_r1cs_witness() const;
};

}

#include "round.tcc"

#endif // __ZETH_MIMC_ROUND_HPP
