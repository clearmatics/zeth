// DISCLAIMER:
// Content taken and adapted from:
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/mimc.hpp

#ifndef __ZETH_MIMC_ROUND_HPP__
#define __ZETH_MIMC_ROUND_HPP__

#include "snarks_alias.hpp"
#include "circuits/circuits-util.hpp"

namespace libzeth {
/*
  MiMCe7_round_gadget enforces correct computation of a MiMC permutation round with exponent 7.
 */
class MiMCe7_round_gadget : public GadgetT {
public:
    const VariableT x;  // round message
    const VariableT k;  // round key
    const FieldT C; // round constant
    const bool add_k_to_result; // variable to add the key after the round
    const VariableT a;  // constraint t^2 variable
    const VariableT b;  // constraint t^4 variable
    const VariableT c;  // constraint t^6 variable
    const VariableT d;  // constraint t^7 variable

public:
    MiMCe7_round_gadget(
        ProtoboardT& pb,
        const VariableT in_x,
        const VariableT in_k,
        const FieldT& in_C,
        const bool in_add_k_to_result,
        const std::string &annotation_prefix
    );

    const VariableT& result() const;  // return d variable
    void generate_r1cs_constraints();
    void generate_r1cs_witness() const;
};

}

#include "round.tcc"

#endif // __ZETH_MIMC_ROUND_HPP
