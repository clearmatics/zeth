// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_TYPES_EXTENDED_PROOF_TCC__
#define __ZETH_TYPES_EXTENDED_PROOF_TCC__

#include "libzeth/core/extended_proof.hpp"
#include "libzeth/core/field_element_utils.hpp"

namespace libzeth
{

template<typename ppT, typename snarkT>
extended_proof<ppT, snarkT>::extended_proof(
    typename snarkT::ProofT &&in_proof,
    libsnark::r1cs_primary_input<libff::Fr<ppT>> &&in_primary_inputs)
{
    proof = in_proof;
    primary_inputs = in_primary_inputs;
}

template<typename ppT, typename snarkT>
const typename snarkT::ProofT &extended_proof<ppT, snarkT>::get_proof() const
{
    return proof;
}

template<typename ppT, typename snarkT>
const libsnark::r1cs_primary_input<libff::Fr<ppT>>
    &extended_proof<ppT, snarkT>::get_primary_inputs() const
{
    return primary_inputs;
}

template<typename ppT, typename snarkT>
std::ostream &extended_proof<ppT, snarkT>::primary_inputs_write_json(
    std::ostream &os) const
{
    os << "[";
    const size_t num_inputs = primary_inputs.size();
    for (size_t i = 0; i < num_inputs; ++i) {
        os << "\n    \"0x"
           << bigint_to_hex<libff::Fr<ppT>>(primary_inputs[i].as_bigint())
           << ((i < num_inputs - 1) ? "\"," : "\"");
    }
    os << "\n  ]";
    return os;
}

template<typename ppT, typename snarkT>
std::ostream &extended_proof<ppT, snarkT>::write_json(std::ostream &os) const
{
    os << "{\n"
          "  \"proof\": ";
    snarkT::proof_write_json(proof, os);
    os << ",\n"
          "  \"inputs\": ";
    primary_inputs_write_json(os);
    os << "\n"
          "}\n";
    return os;
}

} // namespace libzeth

#endif // __ZETH_TYPES_EXTENDED_PROOF_TCC__
