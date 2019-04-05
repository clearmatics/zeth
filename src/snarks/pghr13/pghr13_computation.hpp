#ifndef __ZETH_PGHR13_COMPUTATION_HPP__
#define __ZETH_PGHR13_COMPUTATION_HPP__

#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/gadgetlib1/gadget.hpp>


// We instantiate the ppT (public parameters Template with the public paramaters of the curve we use (alt_bn128))
typedef libff::default_ec_pp ppT; // We use the public parameters of the alt_bn_128 curve to do our operations

namespace libzeth {

    // circuit-wrapper functions //TODO: here I can specify the type
    template<typename ppT>
    libsnark::r1cs_ppzksnark_proof<ppT> gen_proof(libsnark::protoboard<libff::Fr<ppT> > pb, libsnark::r1cs_ppzksnark_proving_key<ppT> proving_key);

    template<typename ppT>
    keyPairT<ppT> gen_trusted_setup(libsnark::protoboard<libff::Fr<ppT> > pb);

    // other functions
    template<typename ppT> 
    void exportVerificationKey(libsnark::r1cs_ppzksnark_keypair<ppT> keypair);

    template<typename ppT> 
    void displayProof(libsnark::r1cs_ppzksnark_proof<ppT> proof);

    template<typename ppT>
    void verificationKeyToJson(libsnark::r1cs_ppzksnark_keypair<ppT> keypair, boost::filesystem::path path = "");

    template<typename ppT> 
    void proofAndInputToJson(libsnark::r1cs_ppzksnark_proof<ppT> proof, libsnark::r1cs_ppzksnark_primary_input<ppT> input, boost::filesystem::path path = "");

    template<typename ppT> 
    void proofToJson(libsnark::r1cs_ppzksnark_proof<ppT> proof, boost::filesystem::path path);

} // libzeth
#include "pghr13_computation.tcc"

#endif // __ZETH_PGHR13_COMPUTATION_HPP__

