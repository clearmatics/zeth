// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CIRCUIT_WRAPPER_HPP__
#define __ZETH_CIRCUIT_WRAPPER_HPP__

#include "libzeth/circuits/joinsplit.tcc"
#include "libzeth/serialization/file_io.hpp"
#include "libzeth/types/note.hpp"

#include "libzeth/snarks_types.hpp"
#include "libzeth/snarks_core_imports.hpp"
#include "libzeth/zeth.h"

namespace libzeth
{

template<
    typename FieldT,
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
    boost::filesystem::path setup_path;
    std::shared_ptr<joinsplit_gadget<
        FieldT,
        HashT,
        HashTreeT,
        NumInputs,
        NumOutputs,
        TreeDepth>>
        joinsplit_g;

    circuit_wrapper(const boost::filesystem::path setup_path = "")
        : setup_path(setup_path){};

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
};

} // namespace libzeth
#include "libzeth/circuit_wrapper.tcc"

#endif // __ZETH_CIRCUIT_WRAPPER_HPP__
