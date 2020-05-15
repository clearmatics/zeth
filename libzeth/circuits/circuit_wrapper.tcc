// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CIRCUITS_CIRCUIT_WRAPPER_TCC__
#define __ZETH_CIRCUITS_CIRCUIT_WRAPPER_TCC__

#include "libzeth/circuits/circuit_wrapper.hpp"

namespace libzeth
{

template<
    typename HashT,
    typename HashTreeT,
    typename ppT,
    typename snarkT,
    size_t NumInputs,
    size_t NumOutputs,
    size_t TreeDepth>
circuit_wrapper<
    HashT,
    HashTreeT,
    ppT,
    snarkT,
    NumInputs,
    NumOutputs,
    TreeDepth>::circuit_wrapper()
{
}

template<
    typename HashT,
    typename HashTreeT,
    typename ppT,
    typename snarkT,
    size_t NumInputs,
    size_t NumOutputs,
    size_t TreeDepth>
typename snarkT::KeypairT circuit_wrapper<
    HashT,
    HashTreeT,
    ppT,
    snarkT,
    NumInputs,
    NumOutputs,
    TreeDepth>::generate_trusted_setup() const
{
    libsnark::protoboard<FieldT> pb;
    joinsplit_gadget<FieldT, HashT, HashTreeT, NumInputs, NumOutputs, TreeDepth>
        g(pb);
    g.generate_r1cs_constraints();

    // Generate a verification and proving key (trusted setup) and write them
    // in a file
    return snarkT::generate_setup(pb);
}

template<
    typename HashT,
    typename HashTreeT,
    typename ppT,
    typename snarkT,
    size_t NumInputs,
    size_t NumOutputs,
    size_t TreeDepth>
libsnark::protoboard<libff::Fr<ppT>> circuit_wrapper<
    HashT,
    HashTreeT,
    ppT,
    snarkT,
    NumInputs,
    NumOutputs,
    TreeDepth>::get_constraint_system() const
{
    libsnark::protoboard<FieldT> pb;
    joinsplit_gadget<FieldT, HashT, HashTreeT, NumInputs, NumOutputs, TreeDepth>
        g(pb);
    g.generate_r1cs_constraints();
    return pb;
}

template<
    typename HashT,
    typename HashTreeT,
    typename ppT,
    typename snarkT,
    size_t NumInputs,
    size_t NumOutputs,
    size_t TreeDepth>
extended_proof<ppT, snarkT> circuit_wrapper<
    HashT,
    HashTreeT,
    ppT,
    snarkT,
    NumInputs,
    NumOutputs,
    TreeDepth>::
    prove(
        const FieldT &root,
        const std::array<joinsplit_input<FieldT, TreeDepth>, NumInputs> &inputs,
        const std::array<zeth_note, NumOutputs> &outputs,
        const bits64 &vpub_in,
        const bits64 &vpub_out,
        const bits256 &h_sig_in,
        const bits256 &phi_in,
        const typename snarkT::ProvingKeyT &proving_key) const
{
    // left hand side and right hand side of the joinsplit
    bits64 lhs_value = vpub_in;
    bits64 rhs_value = vpub_out;

    // Compute the sum on the left hand side of the joinsplit
    for (size_t i = 0; i < NumInputs; i++) {
        lhs_value = bits_add<ZETH_V_SIZE>(lhs_value, inputs[i].note.value);
    }

    // Compute the sum on the right hand side of the joinsplit
    for (size_t i = 0; i < NumOutputs; i++) {
        rhs_value = bits_add<ZETH_V_SIZE>(rhs_value, outputs[i].value);
    }

    // [CHECK] Make sure that the balance between rhs and lfh is respected
    // Used to stop any proof computation that would inevitably fail
    // due to a violation of the constraint:
    // `1 * left_value = right_value` in the JoinSplit circuit
    if (lhs_value != rhs_value) {
        throw std::invalid_argument("invalid joinsplit balance");
    }

    libsnark::protoboard<FieldT> pb;

    joinsplit_gadget<FieldT, HashT, HashTreeT, NumInputs, NumOutputs, TreeDepth>
        g(pb);
    g.generate_r1cs_constraints();
    g.generate_r1cs_witness(
        root, inputs, outputs, vpub_in, vpub_out, h_sig_in, phi_in);

    bool is_valid_witness = pb.is_satisfied();
    std::cout << "******* [DEBUG] Satisfiability result: " << is_valid_witness
              << " *******" << std::endl;

    // Instantiate an extended_proof from the proof we generated and the given
    // primary_input
    return extended_proof<ppT, snarkT>(
        snarkT::generate_proof(pb, proving_key), pb.primary_input());
}

} // namespace libzeth

#endif // __ZETH_CIRCUITS_CIRCUIT_WRAPPER_TCC__
