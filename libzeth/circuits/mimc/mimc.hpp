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
template<typename FieldT, size_t Exponent, size_t NumRounds>
class MiMC_permutation_gadget : public libsnark::gadget<FieldT>
{
private:
    // Round constants only available up to 91 rounds
    static_assert(NumRounds <= 91, "NumRounds must be less than 91");

    // Instantiate round gadget with exponent = Exponent
    using RoundT = MiMC_round_gadget<FieldT, Exponent>;

    // Vector of round constants
    static std::vector<FieldT> round_constants;
    static bool round_constants_initialized;

    // Vector of intermediate result values
    std::array<libsnark::pb_variable<FieldT>, NumRounds> round_results;
    // Vector of MiMC round_gadgets
    std::vector<RoundT> round_gadgets;

public:
    MiMC_permutation_gadget(
        libsnark::protoboard<FieldT> &pb,
        const libsnark::pb_variable<FieldT> &msg,
        const libsnark::pb_variable<FieldT> &key,
        const std::string &annotation_prefix = "MiMCe7_permutation_gadget");

    void generate_r1cs_constraints();
    void generate_r1cs_witness() const;

    const libsnark::pb_variable<FieldT> &result() const;

    // Constants vector initialization
    void setup_sha3_constants();
};

} // namespace libzeth

#include "libzeth/circuits/mimc/mimc.tcc"

#endif // __ZETH_CIRCUITS_MIMC_HPP__
