// DISCLAIMER:
// Content taken and adapted from:
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/mimc.hpp

#ifndef __ZETH_CIRCUITS_MIMC_HPP__
#define __ZETH_CIRCUITS_MIMC_HPP__

#include "libzeth/circuits/mimc/mimc_round.hpp"

namespace libzeth
{

/// MiMC_permutation_gadget enforces correct computation of a MiMC round
/// function applied some number of rounds.
template<typename FieldT, typename RoundT, size_t NumRounds>
class MiMC_permutation_gadget : public libsnark::gadget<FieldT>
{
private:
    // Vector of MiMC round_gadgets
    std::vector<RoundT> round_gadgets;
    // Vector of round constants
    std::vector<FieldT> round_constants;
    // Permutation key
    const libsnark::pb_variable<FieldT> k;

public:
    MiMC_permutation_gadget(
        libsnark::protoboard<FieldT> &pb,
        // Message to encrypt
        const libsnark::pb_variable<FieldT> &x,
        // Encryption key (/permutation seed)
        const libsnark::pb_variable<FieldT> &k,
        const std::string &annotation_prefix = "MiMCe7_permutation_gadget");

    void generate_r1cs_constraints();
    void generate_r1cs_witness() const;

    const libsnark::pb_variable<FieldT> &result() const;

    // Utils functions
    //
    // MiMC round gadgets initialization
    void setup_gadgets(
        const libsnark::pb_variable<FieldT> &x,
        const libsnark::pb_variable<FieldT> &k);
    // Constants vector initialization
    void setup_sha3_constants();
};

template<typename FieldT>
using MiMCe7_permutation_gadget =
    MiMC_permutation_gadget<FieldT, MiMCe7_round_gadget<FieldT>, 91>;

} // namespace libzeth

#include "libzeth/circuits/mimc/mimc.tcc"

#endif // __ZETH_CIRCUITS_MIMC_HPP__
