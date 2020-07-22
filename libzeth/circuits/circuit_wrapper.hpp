// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CIRCUITS_CIRCUIT_WRAPPER_HPP__
#define __ZETH_CIRCUITS_CIRCUIT_WRAPPER_HPP__

#include "libzeth/circuits/joinsplit.tcc"
#include "libzeth/core/extended_proof.hpp"
#include "libzeth/core/note.hpp"
#include "libzeth/zeth_constants.hpp"

namespace libzeth
{

/// Wrapper around the joinsplit circuit, using parameterized schemes for
/// hashing, and a snark scheme for generating keys and proofs.
template<
    typename HashT,
    typename HashTreeT,
    typename ppT,
    typename snarkT,
    size_t NumInputs,
    size_t NumOutputs,
    size_t TreeDepth>
class circuit_wrapper
{
private:
    std::shared_ptr<joinsplit_gadget<
        libff::Fr<ppT>,
        HashT,
        HashTreeT,
        NumInputs,
        NumOutputs,
        TreeDepth>>
        joinsplit_g;

public:
    using Field = libff::Fr<ppT>;

    circuit_wrapper();

    // Generate the trusted setup
    typename snarkT::KeypairT generate_trusted_setup() const;

    // Retrieve the constraint system (intended for debugging purposes).
    libsnark::protoboard<Field> get_constraint_system() const;

    // Generate a proof and returns an extended proof
    extended_proof<ppT, snarkT> prove(
        const Field &root,
        const std::array<joinsplit_input<Field, TreeDepth>, NumInputs> &inputs,
        const std::array<zeth_note, NumOutputs> &outputs,
        const bits64 &vpub_in,
        const bits64 &vpub_out,
        const bits256 &h_sig_in,
        const bits256 &phi_in,
        const typename snarkT::ProvingKeyT &proving_key) const;
};

} // namespace libzeth

#include "libzeth/circuits/circuit_wrapper.tcc"

#endif // __ZETH_CIRCUITS_CIRCUIT_WRAPPER_HPP__
