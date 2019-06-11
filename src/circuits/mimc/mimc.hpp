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
template<typename FieldT>
class MiMCe7_permutation_gadget : public libsnark::gadget<FieldT> {
public:
    std::vector<MiMCe7_round_gadget<FieldT>> m_rounds;  // vector of round gadgets
    std::vector<FieldT> round_constants;  //vector of round constants
    static const int ROUNDS = 91; // nb of rounds
    const libsnark::pb_variable<FieldT> k;  // permutation key

    void _setup_gadgets(
        const libsnark::pb_variable<FieldT> in_x,
        const libsnark::pb_variable<FieldT> in_k);

    void _setup_sha3_constants();

public:
    MiMCe7_permutation_gadget(
        libsnark::protoboard<FieldT>& pb,
        const libsnark::pb_variable<FieldT> in_x,
        const libsnark::pb_variable<FieldT> in_k,
        const std::string& annotation_prefix);

    const libsnark::pb_variable<FieldT>& result() const;
    void generate_r1cs_constraints();
    void generate_r1cs_witness() const;

};

template<typename FieldT>
using MiMC_gadget = MiMCe7_permutation_gadget<FieldT>;

} // libzeth

#include "mimc.tcc"

#endif // __ZETH_MIMC_PERMUTATION_HPP__
