// DISCLAIMER:
// Content taken and adapted from:
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/mimc.hpp

#ifndef __ZETH_CIRCUITS_MIMC_PERMUTATION_HPP__
#define __ZETH_CIRCUITS_MIMC_PERMUTATION_HPP__

#include "libzeth/circuits/mimc/mimc_round.hpp"

namespace libzeth
{

/// MiMC_permutation_gadget enforces correct computation of the MiMC
/// permutation, denoted MiMC_r(k, m) in the Zeth specifications
/// (https://github.com/clearmatics/zeth-specifications), by peforming
/// NumRounds MiMC rounds with the given Exponent. An optional `add_to_result`
/// value can be passed in to be added to the result of the regular MiMC
/// permutation (without requiring extra constraints).
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

    // Common initialization
    MiMC_permutation_gadget(
        libsnark::protoboard<FieldT> &pb,
        const libsnark::pb_linear_combination<FieldT> &msg,
        const libsnark::pb_linear_combination<FieldT> &key,
        const libsnark::pb_variable<FieldT> &result,
        const libsnark::pb_linear_combination<FieldT> &add_to_result,
        const bool have_add_to_result,
        const std::string &annotation_prefix);

public:
    MiMC_permutation_gadget(
        libsnark::protoboard<FieldT> &pb,
        const libsnark::pb_linear_combination<FieldT> &msg,
        const libsnark::pb_linear_combination<FieldT> &key,
        const libsnark::pb_variable<FieldT> &result,
        const std::string &annotation_prefix = "MiMC_permutation_gadget");

    MiMC_permutation_gadget(
        libsnark::protoboard<FieldT> &pb,
        const libsnark::pb_linear_combination<FieldT> &msg,
        const libsnark::pb_linear_combination<FieldT> &key,
        const libsnark::pb_variable<FieldT> &result,
        const libsnark::pb_linear_combination<FieldT> &add_to_result,
        const std::string &annotation_prefix = "MiMC_permutation_gadget");

    void generate_r1cs_constraints();
    void generate_r1cs_witness() const;

    // Constants vector initialization
    void setup_sha3_constants();
};

} // namespace libzeth

#include "libzeth/circuits/mimc/mimc_permutation.tcc"

#endif // __ZETH_CIRCUITS_MIMC_PERMUTATION_HPP__
