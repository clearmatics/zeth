#ifndef __ZETH_EXTENDED_PROOF_HPP__
#define __ZETH_EXTENDED_PROOF_HPP__

#include "debug_helpers.hpp"
#include "zeth.h"
#include "snarks_alias.hpp" // Snark dependent alias for keyPairT, provingKeyT, proofT and keyPairT
#include "snarks_import.hpp" // Snark dependent implementation import for generate_trusted_setup() and prove() functions

namespace libzeth {

/*
 * An extended_proof is a data structure containing a proof and the corresponding primary inputs
 * It corresponds to the data needed for the verifier to be able to run the verifying
 * algorithm.
 **/
template<typename ppT>
class extended_proof {
private:
    std::shared_ptr<proofT<ppT>> proof;
    std::shared_ptr<libsnark::r1cs_primary_input<libff::Fr<ppT>>> primary_inputs;

public:
    extended_proof(proofT<ppT> &in_proof, libsnark::r1cs_primary_input<libff::Fr<ppT>> &in_primary_input);

    proofT<ppT> get_proof();

    libsnark::r1cs_primary_input<libff::Fr<ppT>> get_primary_input();
    
    void write_primary_input(boost::filesystem::path path = "");
    
    void dump_primary_inputs();
    
    void write_proof(boost::filesystem::path path);
    
    void write_extended_proof(boost::filesystem::path path);
    
    void dump_proof();

};

} // libzeth
#include "libsnark_helpers/extended_proof.tcc"

#endif
