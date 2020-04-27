// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_TYPES_EXTENDED_PROOF_HPP__
#define __ZETH_TYPES_EXTENDED_PROOF_HPP__

#include "libzeth/snarks_core_imports.hpp"
#include "libzeth/snarks_types.hpp"
#include "libzeth/serialization/filesystem_util.hpp"
#include "libzeth/zeth.h"

namespace libzeth
{

// An extended_proof is a data structure containing a proof and the
// corresponding primary inputs It corresponds to the data needed for the
// verifier to be able to run the verifying algorithm.
template<typename ppT, typename snarkT> class extended_proof
{
private:
    std::shared_ptr<typename snarkT::ProofT> proof;
    std::shared_ptr<libsnark::r1cs_primary_input<libff::Fr<ppT>>>
        primary_inputs;

public:
    extended_proof(
        typename snarkT::ProofT &in_proof,
        libsnark::r1cs_primary_input<libff::Fr<ppT>> &in_primary_inputs);
    const typename snarkT::ProofT &get_proof() const;
    const libsnark::r1cs_primary_input<libff::Fr<ppT>> &get_primary_inputs()
        const;

    // Write on disk
    void write_primary_inputs(boost::filesystem::path path = "") const;
    void write_proof(boost::filesystem::path path = "") const;
    void write_extended_proof(boost::filesystem::path path = "") const;

    // Display on stdout
    void dump_proof() const;
    void dump_primary_inputs() const;
};

} // namespace libzeth

#include "libzeth/types/extended_proof.tcc"

#endif // __ZETH_TYPES_EXTENDED_PROOF_HPP__
