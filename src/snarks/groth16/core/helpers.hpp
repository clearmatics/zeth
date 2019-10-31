#ifndef __ZETH_HELPERS_HPP__
#define __ZETH_HELPERS_HPP__

#include "libsnark_helpers/debug_helpers.hpp"

#include <boost/filesystem.hpp>
#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

// We instantiate the ppT (public parameters Template with the public paramaters
// of the curve we use (alt_bn128))
typedef libff::default_ec_pp ppT; // We use the public parameters of the
                                  // alt_bn_128 curve to do our operations

namespace libzeth
{

template<typename ppT>
void exportVerificationKey(libsnark::r1cs_gg_ppzksnark_keypair<ppT> keypair);

template<typename ppT>
void displayProof(libsnark::r1cs_gg_ppzksnark_proof<ppT> proof);

template<typename ppT>
void verificationKeyToJson(
    libsnark::r1cs_gg_ppzksnark_keypair<ppT> keypair,
    boost::filesystem::path path = "");

template<typename ppT>
void proofAndInputToJson(
    libsnark::r1cs_gg_ppzksnark_proof<ppT> proof,
    libsnark::r1cs_ppzksnark_primary_input<ppT> input,
    boost::filesystem::path path = "");

template<typename ppT>
void proofToJson(
    libsnark::r1cs_gg_ppzksnark_proof<ppT> proof, boost::filesystem::path path);

} // namespace libzeth
#include "snarks/groth16/core/helpers.tcc"

#endif // __ZETH_HELPERS_HPP__
