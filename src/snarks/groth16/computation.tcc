#ifndef __ZETH_COMPUTATION_TCC__
#define __ZETH_COMPUTATION_TCC__

namespace libzeth {

// Generate the proof and returns a struct {proof, primary_input}
template<typename ppT>
libsnark::r1cs_gg_ppzksnark_proof<ppT> gen_proof(libsnark::protoboard<libff::Fr<ppT> > pb, libsnark::r1cs_gg_ppzksnark_proving_key<ppT> proving_key)
{
    // See: https://github.com/scipr-lab/libsnark/blob/92a80f74727091fdc40e6021dc42e9f6b67d5176/libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp#L81
    // For the definition of r1cs_primary_input and r1cs_auxiliary_input
    libsnark::r1cs_primary_input<libff::Fr<ppT>> primary_input = pb.primary_input();
    libsnark::r1cs_auxiliary_input<libff::Fr<ppT>> auxiliary_input = pb.auxiliary_input();

    // Generate proof from public input, auxiliary input (private/secret data), and proving key
    proofT<ppT> proof = libsnark::r1cs_gg_ppzksnark_prover(proving_key, primary_input, auxiliary_input);

    return proof;
};

// Run the trusted setup and returns a struct {proving_key, verifying_key}
template<typename ppT>
libsnark::r1cs_gg_ppzksnark_keypair<ppT> gen_trusted_setup(libsnark::protoboard<libff::Fr<ppT> > pb)
{
    // Generate verification and proving key (Trusted setup) from the R1CS (defined in the ZoKrates/wraplibsnark.cpp file)
    // This function, basically reduces the R1CS into a QAP, and then encodes the QAP, along with a secret s and its
    // set of powers, plus the alpha, beta, and the rest of the entries, in order to form the CRS
    // (crs_f, shortcrs_f, as denoted in [GGPR12])

    return libsnark::r1cs_gg_ppzksnark_generator<ppT>(pb.get_constraint_system());
};

// Verification of a proof
template<typename ppT>
bool verify(libzeth::extended_proof<ppT> ext_proof, libsnark::r1cs_gg_ppzksnark_verification_key<ppT> verification_key)
{
    return libsnark::r1cs_gg_ppzksnark_verifier_strong_IC<ppT>(verification_key, ext_proof.get_primary_input(), ext_proof.get_proof());
};

} // libzeth

#endif // __ZETH_COMPUTATION_TCC__
