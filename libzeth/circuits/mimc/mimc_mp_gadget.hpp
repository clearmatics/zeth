// DISCLAIMER:
// Content taken and adapted from:
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/mimc.hpp

#ifndef __ZETH_CIRCUITS_MIMC_MP_GADGET_HPP__
#define __ZETH_CIRCUITS_MIMC_MP_GADGET_HPP__

#include "libzeth/circuits/mimc/mimc_permutation_gadget.hpp"

namespace libzeth
{

/// This gadget implements the interface of the HashTreeT template
///
/// MiMC_mp_gadget enforces correct computation of MiMC compression function
/// based on a the Miyaguchi-Preneel compression construct and a
/// MiMC_permutation_gadget instance, PermutationT, operating on FieldT
/// elements.
template<typename FieldT, typename PermutationT>
class MiMC_mp_gadget : public libsnark::gadget<FieldT>
{
private:
    // First input
    libsnark::pb_variable<FieldT> x;
    // Second input
    libsnark::pb_variable<FieldT> y;
    // Permutation gadget
    PermutationT permutation_gadget;
    // Output variable
    libsnark::pb_variable<FieldT> output;

public:
    MiMC_mp_gadget(
        libsnark::protoboard<FieldT> &pb,
        const libsnark::pb_variable<FieldT> x,
        const libsnark::pb_variable<FieldT> y,
        const std::string &annotation_prefix = "MiMC_mp_gadget");

    void generate_r1cs_constraints();
    void generate_r1cs_witness() const;

    // Returns the hash computed
    const libsnark::pb_variable<FieldT> &result() const;

    // Returns the hash (field element)
    static FieldT get_hash(const FieldT x, FieldT y);
};

} // namespace libzeth

#include "libzeth/circuits/mimc/mimc_mp_gadget.tcc"

#endif // __ZETH_CIRCUITS_MIMC_MP_GADGET_HPP__
