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
    const libsnark::pb_variable<FieldT> &x,
    const libsnark::pb_variable<FieldT> &y,
    const libsnark::pb_variable<FieldT> &result,
    const std::string &annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix)
    , x(x)
    , y(y)
    , result(result)
{
    perm_output.allocate(this->pb, FMT(annotation_prefix, " perm_output"));
    permutation_gadget.reset(new PermutationT(
        pb,
        x,
        y,
        perm_output,
        FMT(this->annotation_prefix, " permutation_gadget")));
}

template<typename FieldT, typename PermutationT>
void MiMC_mp_gadget<FieldT, PermutationT>::generate_r1cs_constraints()
{
    // Setting constraints for the permutation gadget
    permutation_gadget->generate_r1cs_constraints();

    // Adding constraint for the Miyaguchi-Preneel equation
    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(perm_output + x + y, 1, result),
        FMT(this->annotation_prefix, " out=k+E_k(m_i)+m_i"));
}

template<typename FieldT, typename PermutationT>
void MiMC_mp_gadget<FieldT, PermutationT>::generate_r1cs_witness() const
{
    // Generating witness for the gadget
    permutation_gadget->generate_r1cs_witness();

    // Filling output variables for Miyaguchi-Preenel equation
    this->pb.val(result) =
        this->pb.val(y) + this->pb.val(perm_output) + this->pb.val(x);
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
