#ifndef __ZETH_EXTENDED_PROOF_HPP__
#define __ZETH_EXTENDED_PROOF_HPP__

#include "debug_helpers.hpp"
#include "snarks_alias.hpp"
#include "zeth.h"

namespace libzeth
{

// An extended_proof is a data structure containing a proof and the
// corresponding primary inputs It corresponds to the data needed for the
// verifier to be able to run the verifying algorithm.
template<typename ppT> class extended_proof
{
private:
    std::shared_ptr<proofT<ppT>> proof;
    std::shared_ptr<libsnark::r1cs_primary_input<libff::Fr<ppT>>>
        primary_inputs;

public:
    extended_proof(
        proofT<ppT> &in_proof,
        libsnark::r1cs_primary_input<libff::Fr<ppT>> &in_primary_input);
    const proofT<ppT> &get_proof() const;
    const libsnark::r1cs_primary_input<libff::Fr<ppT>> &get_primary_input()
        const;

    // Write on disk
    void write_primary_input(boost::filesystem::path path = "") const;
    void write_proof(boost::filesystem::path path = "") const;
    void write_extended_proof(boost::filesystem::path path = "") const;

    // Display on stdout
    void dump_proof() const;
    void dump_primary_inputs() const;
};

} // namespace libzeth

#include "libsnark_helpers/extended_proof.tcc"

#endif
