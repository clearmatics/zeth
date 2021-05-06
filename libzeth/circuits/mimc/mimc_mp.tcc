// DISCLAIMER:
// Content taken and adapted from:
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/mimc.hpp

#ifndef __ZETH_CIRCUITS_MIMC_MP_TCC__
#define __ZETH_CIRCUITS_MIMC_MP_TCC__

#include "mimc_mp.hpp"

namespace libzeth
{

template<typename FieldT, typename PermutationT>
MiMC_mp_gadget<FieldT, PermutationT>::MiMC_mp_gadget(
    libsnark::protoboard<FieldT> &pb,
    const libsnark::pb_linear_combination<FieldT> &x,
    const libsnark::pb_linear_combination<FieldT> &y,
    const libsnark::pb_variable<FieldT> &result,
    const std::string &annotation_prefix)
{
    // Adding x+y to the output of the permutation yields the Miyaguchi-Preneel
    // equation:
    //
    //   result = permutation(x, y) + x + y

    libsnark::pb_linear_combination<FieldT> x_plus_y;
    x_plus_y.assign(pb, x + y);
    permutation_gadget.reset(new PermutationT(
        pb, x, y, result, x_plus_y, FMT(annotation_prefix, " MP")));
}

template<typename FieldT, typename PermutationT>
void MiMC_mp_gadget<FieldT, PermutationT>::generate_r1cs_constraints()
{
    permutation_gadget->generate_r1cs_constraints();
}

template<typename FieldT, typename PermutationT>
void MiMC_mp_gadget<FieldT, PermutationT>::generate_r1cs_witness() const
{
    permutation_gadget->generate_r1cs_witness();
}

// Returns the hash of two elements
template<typename FieldT, typename PermutationT>
FieldT MiMC_mp_gadget<FieldT, PermutationT>::get_hash(const FieldT x, FieldT y)
{
    libsnark::protoboard<FieldT> pb;

    libsnark::pb_variable<FieldT> pb_x;
    libsnark::pb_variable<FieldT> pb_y;
    libsnark::pb_variable<FieldT> result;

    // Allocates and fill with the x and y
    pb_x.allocate(pb, "x");
    pb.val(pb_x) = x;

    pb_y.allocate(pb, "y");
    pb.val(pb_y) = y;

    result.allocate(pb, "result");

    // Initialize the Hash
    MiMC_mp_gadget<FieldT, PermutationT> mimc_hasher(
        pb, pb_x, pb_y, result, " mimc_hash");

    // Computes the hash
    mimc_hasher.generate_r1cs_constraints();
    mimc_hasher.generate_r1cs_witness();

    // Returns the hash
    return pb.val(result);
}

} // namespace libzeth

#endif // __ZETH_CIRCUITS_MIMC_MP_TCC__
