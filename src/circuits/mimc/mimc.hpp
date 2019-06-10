// DISCLAIMER:
// Content taken and adapted from:
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/mimc.hpp

#ifndef __ZETH_MIMC_PERMUTATION_HPP__
#define __ZETH_MIMC_PERMUTATION_HPP__

#include "snarks_alias.hpp"
#include "round.hpp"

namespace libzeth  {
/*
  MiMCe7_permutation enforces correct computation of a MiMC permutation with exponent 7
  */
class MiMCe7_permutation_gadget : public GadgetT {
public:
    std::vector<MiMCe7_round_gadget> m_rounds;
    std::vector<FieldT> round_constants;
    static const int ROUNDS = 91;
    const VariableT k;

    void _setup_gadgets(
        const VariableT in_x,
        const VariableT in_k);

    void _setup_sha3_constants();

public:
    MiMCe7_permutation_gadget(
        ProtoboardT& pb,
        const VariableT in_x,
        const VariableT in_k,
        const std::string& annotation_prefix);

    const VariableT& result() const;

    void generate_r1cs_constraints();

    void generate_r1cs_witness() const;

};

using MiMC_gadget = MiMCe7_permutation_gadget;

} // libzeth

#include "mimc.tcc"

#endif // __ZETH_MIMC_PERMUTATION_HPP__
