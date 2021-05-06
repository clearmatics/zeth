// DISCLAIMER:
// Content taken and adapted from:
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/mimc.hpp

#ifndef __ZETH_CIRCUITS_MIMC_MP_HPP__
#define __ZETH_CIRCUITS_MIMC_MP_HPP__

#include "libzeth/circuits/mimc/mimc_permutation.hpp"

namespace libzeth
{

/// This gadget implements the interface of the HashTreeT template.
///
/// MiMC_mp_gadget enforces correct computation of the MiMC compression
/// function, based on a the Miyaguchi-Preneel compression construct using a
/// MiMC_permutation_gadget instance, PermutationT, operating on FieldT
/// elements.
///
/// This class contains only an instance of PermutationT, with parameters
/// configured to make it efficiently compute Miyaguchi-Preneel. As such, it
/// may appear as first sight that it should inherit from PermutationT. We do
/// not inherit from PermutationT, either publicly (because the "is-a"
/// relationship does not hold in general), or privately (because the
/// pb_linear_combination interface does not support immediate construction of
/// `x + y`, making the constructor very awkard - this is also the reason that
/// a pointer is required, rather than a simple instance of PermutationT).
/// Further, we do not inherit from libsnark::gadget<>, as it is not necessary
/// and would just add unused data to the class.
template<typename FieldT, typename PermutationT> class MiMC_mp_gadget
{
private:
    std::shared_ptr<PermutationT> permutation_gadget;

public:
    MiMC_mp_gadget(
        libsnark::protoboard<FieldT> &pb,
        const libsnark::pb_linear_combination<FieldT> &x,
        const libsnark::pb_linear_combination<FieldT> &y,
        const libsnark::pb_variable<FieldT> &result,
        const std::string &annotation_prefix = "MiMC_mp_gadget");

    void generate_r1cs_constraints();
    void generate_r1cs_witness() const;

    // Returns the hash (field element)
    static FieldT get_hash(const FieldT x, FieldT y);
};

} // namespace libzeth

#include "libzeth/circuits/mimc/mimc_mp.tcc"

#endif // __ZETH_CIRCUITS_MIMC_MP_HPP__
