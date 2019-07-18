// DISCLAIMER:
// Content taken and adapted from:
// https://github.com/HarryR/ethsnarks/blob/master/src/gadgets/mimc.hpp

#ifndef __ZETH_MIMC_PERMUTATION_TCC__
#define __ZETH_MIMC_PERMUTATION_TCC__

namespace libzeth {
template<typename FieldT>
void MiMCe7_permutation_gadget<FieldT>::setup_gadgets(
    const libsnark::pb_variable<FieldT> x,
    const libsnark::pb_variable<FieldT> k)
{
    for( size_t i = 0; i < ROUNDS; i++ )
    {
        // setting the input of the next round with the output variable of the previous round (except for round 0)
        const auto& round_x = (i == 0 ? x : round_gadgets.back().result() );

        bool is_last = (i == (ROUNDS-1));

        // initializing and the adding the current round gadget into the rounds gadget vector, picking the relative constant
        round_gadgets.emplace_back(this->pb, round_x, k, round_constants[i], is_last, FMT(this->annotation_prefix, ".round[%d]", i));
    }
}
template<typename FieldT>
MiMCe7_permutation_gadget<FieldT>::MiMCe7_permutation_gadget(
    libsnark::protoboard<FieldT>& pb,
    const libsnark::pb_variable<FieldT> x,
    const libsnark::pb_variable<FieldT> k,
    const std::string& round_constant_iv,
    const std::string& annotation_prefix
) :
    libsnark::gadget<FieldT>(pb, annotation_prefix),
    k(k)
{
    //We first initialize the round constants
    setup_sha3_constants(round_constant_iv);

    //Then we initialize the round gadgets
    setup_gadgets(x, k);
}

template<typename FieldT>
void MiMCe7_permutation_gadget<FieldT>::generate_r1cs_constraints() {
    //For each round, generates the constraints for each round gadget
    for( auto& gadget : round_gadgets )
    {
        gadget.generate_r1cs_constraints();
    }
}

template<typename FieldT>
void MiMCe7_permutation_gadget<FieldT>::generate_r1cs_witness() const {
    //For each round, generates the witness for each round gadget
    for( auto& gadget : round_gadgets )
    {
        gadget.generate_r1cs_witness();
    }

}

template<typename FieldT>
const libsnark::pb_variable<FieldT>& MiMCe7_permutation_gadget<FieldT>::result () const {
    // Returns the result of the last encryption / permutation
    return round_gadgets.back().result();
}



#include "round_constants.tcc"


}  // namespace libzeth

#endif // __ZETH_MIMC_PERMUTATION_TCC__
