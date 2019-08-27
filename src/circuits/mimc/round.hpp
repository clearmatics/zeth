// DISCLAIMER:
// Content taken and adapted from:
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/mimc.hpp

#ifndef __ZETH_MIMC_ROUND_HPP__
#define __ZETH_MIMC_ROUND_HPP__

#include "circuits/circuits-util.hpp"
#include "snarks_alias.hpp"

#include <libsnark/gadgetlib1/gadget.hpp>

// MiMCe7_round_gadget enforces correct computation of a MiMC permutation round
// with exponent 7. In MiMC permutation last round differs from the others since
// the key is added again. We use a boolean variable `add_k_to_result` to manage
// this case.

namespace libzeth
{

template<typename FieldT>
class MiMCe7_round_gadget : public libsnark::gadget<FieldT>
{
private:
    // Message of the current round
    const libsnark::pb_variable<FieldT> x;
    // Key of the current round
    const libsnark::pb_variable<FieldT> k;
    // Round constant of the current round
    const FieldT c;
    // Boolean variable to add the key after the round
    const bool add_k_to_result;

    // Intermediary var for computing t**2
    libsnark::pb_variable<FieldT> t2;
    // Intermediary var for computing t**4
    libsnark::pb_variable<FieldT> t4;
    // Intermediary var for computing t**6
    libsnark::pb_variable<FieldT> t6;
    // Intermediary result for computing t**7 (or t ** 7 + k depending on
    // add_k_to_result)
    libsnark::pb_variable<FieldT> t7;

public:
    MiMCe7_round_gadget(
        libsnark::protoboard<FieldT> &pb,
        // Message of the current round
        const libsnark::pb_variable<FieldT> x,
        // Key of the current round
        const libsnark::pb_variable<FieldT> k,
        // Round constant of the current round
        const FieldT &c,
        // Boolean variable to add the key after the round
        const bool add_k_to_result,
        const std::string &annotation_prefix = "MiMCe7_round_gadget");

    void generate_r1cs_constraints();
    void generate_r1cs_witness() const;

    // Returns round result t ** 7 + add_k_to_result * k
    // where t = (x + k + c)
    const libsnark::pb_variable<FieldT> &result() const;
};

} // namespace libzeth
#include "round.tcc"

#endif // __ZETH_MIMC_ROUND_HPP__
