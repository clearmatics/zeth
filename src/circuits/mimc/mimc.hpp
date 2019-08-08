// DISCLAIMER:
// Content taken and adapted from:
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/mimc.hpp

#ifndef __ZETH_MIMC_PERMUTATION_HPP__
#define __ZETH_MIMC_PERMUTATION_HPP__

#include "snarks_alias.hpp"
#include "round.hpp"

/*
 * MiMCe7_permutation_gadget enforces correct computation of a MiMC permutation with exponent 7 and rounds 91. 
 * It makes use of MiMCe7_round_gadget to enforce correct computation in each round.
**/

namespace libzeth  {

template<typename FieldT>
class MiMCe7_permutation_gadget : public libsnark::gadget<FieldT> {
private:
    std::vector<MiMCe7_round_gadget<FieldT>> round_gadgets; // Vector of MiMC round_gadgets
    std::vector<FieldT> round_constants; // Vector of round constants
    const libsnark::pb_variable<FieldT> k; // Permutation key

public:
    static const int ROUNDS = 91; // Nb of rounds suggested by the MiMC paper

    MiMCe7_permutation_gadget(
        libsnark::protoboard<FieldT>& pb,
        const libsnark::pb_variable<FieldT> x, // Message to encrypt
        const libsnark::pb_variable<FieldT> k, // Encryption key (/permutation seed)
        const std::string& annotation_prefix = "MiMCe7_permutation_gadget"
    );

    void generate_r1cs_constraints();
    void generate_r1cs_witness() const;

    const libsnark::pb_variable<FieldT>& result() const;

    // Utils functions
    //
    // MiMC round gadgets initialization
    void setup_gadgets(const libsnark::pb_variable<FieldT> x, const libsnark::pb_variable<FieldT> k);
    // Constants vector initialization
    void setup_sha3_constants();
};

} // libzeth
#include "mimc.tcc"

#endif // __ZETH_MIMC_PERMUTATION_HPP__
