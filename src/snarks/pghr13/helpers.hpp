#ifndef __ZETH_HELPERS_HPP__
#define __ZETH_HELPERS_HPP__

#include "libsnark_helpers/debug_helpers.hpp"

#include <boost/filesystem.hpp>
#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

// We instantiate the ppT (public parameters Template with the public paramaters
// of the curve we use (alt_bn128))
typedef libff::default_ec_pp ppT;

namespace libzeth
{

template<typename ppT>
void export_verification_key(libsnark::r1cs_ppzksnark_keypair<ppT> keypair);
template<typename ppT>
void display_proof(libsnark::r1cs_ppzksnark_proof<ppT> proof);
template<typename ppT>
void verification_key_to_json(
    libsnark::r1cs_ppzksnark_keypair<ppT> keypair,
    boost::filesystem::path path = "");
template<typename ppT>
void proof_and_inputs_to_json(
    libsnark::r1cs_ppzksnark_proof<ppT> proof,
    libsnark::r1cs_ppzksnark_primary_input<ppT> input,
    boost::filesystem::path path = "");
template<typename ppT>
void proof_to_json(
    libsnark::r1cs_ppzksnark_proof<ppT> proof, boost::filesystem::path path);

} // namespace libzeth
#include "snarks/pghr13/helpers.tcc"

#endif // __ZETH_HELPERS_HPP__
