// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CIRCUITS_CIRCUIT_WRAPPER_HPP__
#define __ZETH_CIRCUITS_CIRCUIT_WRAPPER_HPP__

#include "libzeth/circuits/circuit_constants.hpp"
#include "libzeth/circuits/joinsplit.tcc"
#include "libzeth/core/note.hpp"
#include "libzeth/serialization/file_io.hpp"

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
public:
    using FieldT = libff::Fr<ppT>;

    circuit_wrapper(const boost::filesystem::path setup_path = "");

    // Generate the trusted setup
    typename snarkT::KeypairT generate_trusted_setup() const;

#ifdef DEBUG
    // Used to debug the constraint system
    // Exports the r1cs to json and write to debug folder
    void dump_constraint_system(boost::filesystem::path file_path) const;
#endif

    // Generate a proof and returns an extended proof
    extended_proof<ppT, snarkT> prove(
        const FieldT &root,
        const std::array<joinsplit_input<FieldT, TreeDepth>, NumInputs> &inputs,
        const std::array<zeth_note, NumOutputs> &outputs,
        bits64 vpub_in,
        bits64 vpub_out,
        const bits256 h_sig_in,
        const bits256 phi_in,
        const typename snarkT::ProvingKeyT &proving_key) const;

private:
    boost::filesystem::path setup_path;
    std::shared_ptr<joinsplit_gadget<
        FieldT,
        HashT,
        HashTreeT,
        NumInputs,
        NumOutputs,
        TreeDepth>>
        joinsplit_g;
};

} // namespace libzeth

#include "libzeth/circuits/circuit_wrapper.tcc"

#endif // __ZETH_CIRCUITS_CIRCUIT_WRAPPER_HPP__
