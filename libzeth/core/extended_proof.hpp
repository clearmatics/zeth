// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CORE_EXTENDED_PROOF_HPP__
#define __ZETH_CORE_EXTENDED_PROOF_HPP__

#include "libzeth/core/include_libsnark.hpp"
#include "libzeth/serialization/filesystem_util.hpp"

namespace libzeth
{

// An extended_proof is a data structure containing a proof and the
// corresponding primary inputs It corresponds to the data needed for the
// verifier to be able to run the verifying algorithm.
template<typename ppT, typename snarkT> class extended_proof
{
private:
    typename snarkT::proof proof;
    libsnark::r1cs_primary_input<libff::Fr<ppT>> primary_inputs;

public:
    extended_proof(
        typename snarkT::proof &&in_proof,
        libsnark::r1cs_primary_input<libff::Fr<ppT>> &&in_primary_inputs);
    const typename snarkT::proof &get_proof() const;

    const libsnark::r1cs_primary_input<libff::Fr<ppT>> &get_primary_inputs()
        const;

    std::ostream &write_json(std::ostream &) const;
};

} // namespace libzeth

#include "libzeth/core/extended_proof.tcc"

#endif // __ZETH_CORE_EXTENDED_PROOF_HPP__
