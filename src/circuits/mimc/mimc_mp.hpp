// DISCLAIMER:
// Content taken and adapted from:
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/mimc.hpp

#ifndef __ZETH_MIMC_MP_HPP__
#define __ZETH_MIMC_MP_HPP__

#include "snarks_alias.hpp"
#include "mimc.hpp"

/*
 * This gadget implements the interface of the HashTreeT template
 *
 * MiMC_mp_gadget enforces correct computation of MiMC compression function
 * based on a the Miyaguchi-Preneel compression construct and MiMC block cipher on Z_p with exponent 7 (and 91 rounds)
 * p is given by the size(FieldT)
**/

namespace libzeth {

template<typename FieldT>
class MiMC_mp_gadget : public libsnark::gadget<FieldT> {
private:
    libsnark::pb_variable<FieldT> x; // First input
    libsnark::pb_variable<FieldT> y; // Second input
    MiMCe7_permutation_gadget<FieldT> permutation_gadget; // Permutation gadget
    libsnark::pb_variable<FieldT> output; // Output variable

public:
    MiMC_mp_gadget(
        libsnark::protoboard<FieldT> &pb,
        const libsnark::pb_variable<FieldT> x,
        const libsnark::pb_variable<FieldT> y,
        const std::string &annotation_prefix = "MiMC_mp_gadget"
    );

    void generate_r1cs_constraints ();
    void generate_r1cs_witness () const;

    // Returns the hash computed
    const libsnark::pb_variable<FieldT>& result() const;

    // Returns the hash (field element)
    static FieldT get_hash(const FieldT x, FieldT y);
};

} // libzeth
#include "mimc_mp.tcc"

#endif // __ZETH_MIMC_MP_HPP__
