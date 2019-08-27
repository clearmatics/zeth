#ifndef __ZETH_EXTENDED_PROOF_HPP__
#define __ZETH_EXTENDED_PROOF_HPP__

#include "debug_helpers.hpp"
#include "zeth.h"
#include "snarks_alias.hpp" // Snark dependent alias for keyPairT, provingKeyT, verificationKeyT, and proofT

namespace libzeth {

// An extended_proof is a data structure containing a proof and the
// corresponding primary inputs It corresponds to the data needed for the
// verifier to be able to run the verifying algorithm.
template<typename ppT>
class extended_proof {
private:
    std::shared_ptr<proofT<ppT>> proof;
    std::shared_ptr<libsnark::r1cs_primary_input<libff::Fr<ppT>>> primary_inputs;

public:
    extended_proof(proofT<ppT> &in_proof, libsnark::r1cs_primary_input<libff::Fr<ppT>> &in_primary_input);
    proofT<ppT> get_proof();
    libsnark::r1cs_primary_input<libff::Fr<ppT>> get_primary_input();

    // Write on disk
    void write_primary_input(boost::filesystem::path path = "");
    void write_proof(boost::filesystem::path path = "");
    void write_extended_proof(boost::filesystem::path path = "");

    // Display on stdout
    void dump_proof();
    void dump_primary_inputs();
};

} // libzeth
#include "libsnark_helpers/extended_proof.tcc"

#endif
