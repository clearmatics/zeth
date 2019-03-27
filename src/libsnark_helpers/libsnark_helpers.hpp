// DISCLAIMER:
// Content taken and adapted from:
// wraplibsnark.cpp (originally written by Jacob Eberhardt and Dennis Kuhnert)

#ifndef __LIBSNARK_HELPERS_HPP__
#define __LIBSNARK_HELPERS_HPP__

#include <stdbool.h>
#include <stdint.h>
#include <fstream>
#include <sstream>
#include <iostream>
#include <cassert>
#include <iomanip>

#include <boost/filesystem.hpp>

// Contains definition of alt_bn128 ec public parameters
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

#include <libff/common/default_types/ec_pp.hpp>

// Contains required interfaces and types (keypair, proof, generator, prover, verifier)
#include "zeth.h"
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/gadgetlib1/gadget.hpp>

namespace libzeth {

// -- Defined in the CPP file -- //
libff::bigint<libff::alt_bn128_r_limbs> libsnarkBigintFromBytes(const uint8_t* _x);
std::string HexStringFromLibsnarkBigint(libff::bigint<libff::alt_bn128_r_limbs> _x);
std::string outputPointG1AffineAsHex(libff::alt_bn128_G1 _p);
std::string outputPointG2AffineAsHex(libff::alt_bn128_G2 _p);

boost::filesystem::path getPathToSetupDir();
boost::filesystem::path getPathToDebugDir();

bool replace(std::string& str, const std::string& from, const std::string& to);

// -- Defined in the TCC file -- //
template<typename serializableT> void writeToFile(boost::filesystem::path path, serializableT& obj);
template<typename serializableT> serializableT loadFromFile(boost::filesystem::path path);

template<typename ppT> void serializeProvingKeyToFile(provingKeyT<ppT> &pk, boost::filesystem::path pk_path);
template<typename ppT> provingKeyT<ppT> deserializeProvingKeyFromFile(boost::filesystem::path pk_path);
template<typename ppT> void serializeVerificationKeyToFile(verificationKeyT<ppT> &vk, boost::filesystem::path vk_path);
template<typename ppT> verificationKeyT<ppT> deserializeVerificationKeyFromFile(boost::filesystem::path vk_path);

template<typename ppT> void exportVerificationKey(libsnark::r1cs_ppzksnark_keypair<ppT> keypair);
template<typename ppT> void exportVerificationKey(libsnark::r1cs_gg_ppzksnark_keypair<ppT> keypair);

template<typename ppT> void displayProof(libsnark::r1cs_ppzksnark_proof<ppT> proof);
template<typename ppT> void displayProof(libsnark::r1cs_gg_ppzksnark_proof<ppT> proof);

template<typename ppT> void verificationKeyToJson(libsnark::r1cs_ppzksnark_keypair<ppT> keypair, boost::filesystem::path path = "");
template<typename ppT> void verificationKeyToJson(libsnark::r1cs_gg_ppzksnark_verification_key<ppT> vk, boost::filesystem::path path);

template<typename ppT> void proofToJson(libsnark::r1cs_ppzksnark_proof<ppT> proof, boost::filesystem::path path);
template<typename ppT> void proofToJson(libsnark::r1cs_gg_ppzksnark_proof<ppT> proof, boost::filesystem::path path);

template<typename ppT> void writeSetup(keyPairT<ppT> keypair, boost::filesystem::path setup_dir = "");

template<typename ppT> void r1csConstraintsToJson(libsnark::linear_combination<libff::Fr<ppT> > constraints, boost::filesystem::path path = "");
template<typename ppT> void fillJsonConstraintsInSs(libsnark::linear_combination<libff::Fr<ppT> > constraints, std::stringstream& ss);
template<typename ppT> void arrayToJson(libsnark::protoboard<libff::Fr<ppT> > pb, uint input_variables, boost::filesystem::path path = "");
template<typename ppT> void r1csToJson(libsnark::protoboard<libff::Fr<ppT> > pb, uint input_variables, boost::filesystem::path path = "");

template<typename ppT> void proofAndInputToJson(libsnark::r1cs_ppzksnark_proof<ppT> proof, libsnark::r1cs_ppzksnark_primary_input<ppT> input, boost::filesystem::path path = "");
template<typename ppT> void proofAndInputToJson(libsnark::r1cs_gg_ppzksnark_proof<ppT> proof, libsnark::r1cs_gg_ppzksnark_primary_input<ppT> input, boost::filesystem::path path = "");

template<typename ppT> void primaryInputToJson(libsnark::r1cs_primary_input<libff::Fr<ppT>> input, boost::filesystem::path = ""); 

// Display
template<typename ppT> void displayPrimaryInput(libsnark::r1cs_primary_input<libff::Fr<ppT>> input);


} // libzeth
#include "libsnark_helpers/libsnark_helpers.tcc"

#endif
