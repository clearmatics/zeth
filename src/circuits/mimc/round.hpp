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
  * In MiMC permutation last round differs from the others since the key is added again. We use a boolean variable `add_k_to_result` to manage this case.
  */
template<typename FieldT>
class MiMCe7_round_gadget : libsnark::gadget<FieldT> {
public:
    const libsnark::pb_variable<FieldT> x;  // round message
    const libsnark::pb_variable<FieldT> k;  // round key
    const FieldT c;                         // round constant
    const bool add_k_to_result;             // variable to add the key after the round

    // Intermediary variables
    libsnark::pb_variable<FieldT> t2;
    libsnark::pb_variable<FieldT> t4;
    libsnark::pb_variable<FieldT> t6;
    libsnark::pb_variable<FieldT> t7;

public:
    MiMCe7_round_gadget(
        libsnark::protoboard<FieldT>& pb,
        const libsnark::pb_variable<FieldT> x,
        const libsnark::pb_variable<FieldT> k,
        const FieldT& c,
        const bool add_k_to_result,
        const std::string &annotation_prefix = "MiMCe7_round_gadget"
    );

    const libsnark::pb_variable<FieldT>& result() const;  // returns output variable

    void generate_r1cs_constraints();

    void generate_r1cs_witness() const;
};

}   // libzeth

#include "round.tcc"

#endif // __ZETH_MIMC_ROUND_HPP
