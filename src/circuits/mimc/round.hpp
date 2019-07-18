// DISCLAIMER:
// Content taken and adapted from:
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/mimc.hpp

#ifndef __ZETH_MIMC_ROUND_HPP__
#define __ZETH_MIMC_ROUND_HPP__

#include "snarks_alias.hpp"

#include <libsnark/gadgetlib1/gadget.hpp>
#include "circuits/circuits-util.hpp"

namespace libzeth {
 /*
  * MiMCe7_round_gadget enforces correct computation of a MiMC permutation round with exponent 7.
  * In MiMC permutation last round differs from the others since the key is added again. We use a boolean variable `add_k_to_result` to manage this case.
  */
template<typename FieldT>
class MiMCe7_round_gadget : public libsnark::gadget<FieldT> {
public:
    const libsnark::pb_variable<FieldT> x;          // The message of the current round
    const libsnark::pb_variable<FieldT> k;          // The key of the current round
    const FieldT c;                                 // The round constant of the current round
    const bool add_k_to_result;                     // Boolean variable to add the key after the round

    // Intermediary variables
    // t  = x + k + c is a linear combination, as such no pb_variable is needed
    libsnark::pb_variable<FieldT> t2;               // Intermediary var for computing t**2
    libsnark::pb_variable<FieldT> t4;               // Intermediary var for computing t**4
    libsnark::pb_variable<FieldT> t6;               // Intermediary var for computing t**6
    libsnark::pb_variable<FieldT> t7;               // Intermediary result for computing t**7 (or t**7+k depending on add_k_to_result)

public:
    MiMCe7_round_gadget(
        libsnark::protoboard<FieldT>& pb,
        const libsnark::pb_variable<FieldT> x,      // The message of the current round
        const libsnark::pb_variable<FieldT> k,      // The key of the current round
        const FieldT& c,                            // The round constant of the current round
        const bool add_k_to_result,                 // Boolean variable to add the key after the round
        const std::string &annotation_prefix = "MiMCe7_round_gadget"
    );

    void generate_r1cs_constraints();

    void generate_r1cs_witness() const;

    // Returns round result (x + k + c) **7  + add_k_to_result * k
    const libsnark::pb_variable<FieldT>& result() const;

};

}   // libzeth

#include "round.tcc"

#endif // __ZETH_MIMC_ROUND_HPP
