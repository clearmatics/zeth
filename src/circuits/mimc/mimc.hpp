// DISCLAIMER:
// Content taken and adapted from:
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/mimc.hpp

#ifndef __ZETH_MIMC_PERMUTATION_HPP__
#define __ZETH_MIMC_PERMUTATION_HPP__

#include "snarks_alias.hpp"
#include "round.hpp"

namespace libzeth  {
 /*
  * MiMCe7_permutation_gadget enforces correct computation of a MiMC permutation with exponent 7. It makes use of MiMCe7_round_gadget to enforce correct computation in each of the 91 rounds.
  */
template<typename FieldT>
class MiMCe7_permutation_gadget : public libsnark::gadget<FieldT> {
public:
    std::vector<MiMCe7_round_gadget<FieldT>> round_gadgets;     // Vector of MiMC round gadgets
    std::vector<FieldT> round_constants;                        // Current Vector of round constants
    std::map<std::string, std::vector<FieldT> > round_constants_map; // Map of Vector of round constants
    static const int ROUNDS = 91;                               // Nb of rounds suggested by the MiMC paper 
    const libsnark::pb_variable<FieldT> k;                      // The permutation key

    // utility functions
    // MiMC round gadgets initialization
    void setup_gadgets(
        const libsnark::pb_variable<FieldT> x,
        const libsnark::pb_variable<FieldT> k);

    //Constants vector initialization
    void setup_sha3_constants(const std::string& round_constant_iv);

public:
    MiMCe7_permutation_gadget(
        libsnark::protoboard<FieldT>& pb,
        const libsnark::pb_variable<FieldT> x,                  // The message to encrypt
        const libsnark::pb_variable<FieldT> k,                  // The encryption key (/permutation seed)
        const std::string& round_constant_iv,
        const std::string& annotation_prefix = "MiMCe7_permutation_gadget");

    void generate_r1cs_constraints();

    void generate_r1cs_witness() const;

    const libsnark::pb_variable<FieldT>& result() const;

};

template<typename FieldT>
using MiMC_gadget = MiMCe7_permutation_gadget<FieldT>;

} // libzeth

#include "mimc.tcc"

#endif // __ZETH_MIMC_PERMUTATION_HPP__
