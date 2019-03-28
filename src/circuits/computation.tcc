#ifndef __ZETH_COMPUTATION_TCC__
#define __ZETH_COMPUTATION_TCC__

#include "libsnark_helpers/extended_proof.hpp"

namespace libzeth {

// Generate the proof and returns a struct {proof, primary_input}
template<typename ppT>//TODO recover provingKey from KeyPair
extended_proof<ppT> gen_proof(libsnark::protoboard<libff::Fr<ppT> > pb, provingKeyT<ppT> proving_key)
{
    // See: https://github.com/scipr-lab/libsnark/blob/92a80f74727091fdc40e6021dc42e9f6b67d5176/libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp#L81
    // For the definition of r1cs_primary_input and r1cs_auxiliary_input
    libsnark::r1cs_primary_input<libff::Fr<ppT>> primary_input = pb.primary_input();
    libsnark::r1cs_auxiliary_input<libff::Fr<ppT>> auxiliary_input = pb.auxiliary_input();

    // Generate proof from public input, auxiliary input (private/secret data), and proving key
    proofT<ppT> proof = libsnark::r1cs_ppzksnark_prover(proving_key, primary_input, auxiliary_input);

    // Instantiate an extended_proof from the proof we generated and the given primary_input
    extended_proof<ppT> ext_proof = extended_proof<ppT>(proof, primary_input);
    return ext_proof;
}

// Run the trusted setup and returns a struct {proving_key, verifying_key}
template<typename ppT>
keyPairT<ppT> gen_trusted_setup(libsnark::protoboard<libff::Fr<ppT> > pb)
{
    // Generate verification and proving key (Trusted setup) from the R1CS (defined in the ZoKrates/wraplibsnark.cpp file)
	// This function, basically reduces the R1CS into a QAP, and then encodes the QAP, along with a secret s and its
	// set of powers, plus the alpha, beta, gamma, and the rest of the entries, in order to form the CRS
	// (crs_f, shortcrs_f, as denoted in [GGPR12]) 
    
    //TODO: find another solution. Here it is difficult make overloading
    switch(SNARK) {
        case 1 : return libsnark::r1cs_ppzksnark_generator<ppT>(pb.get_constraint_system());
        //case 2 : return libsnark::r1cs_gg_ppzksnark_generator<ppT>(pb.get_constraint_system()); TODO: fix this
    }
}

} // libzeth

#endif
