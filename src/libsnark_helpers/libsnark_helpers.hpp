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
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
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

template<typename ppT> void serializeProvingKeyToFile(libsnark::r1cs_ppzksnark_proving_key<ppT> pk, boost::filesystem::path pk_path);
template<typename ppT> libsnark::r1cs_ppzksnark_proving_key<ppT> deserializeProvingKeyFromFile(boost::filesystem::path pk_path);
template<typename ppT> void serializeVerificationKeyToFile(libsnark::r1cs_ppzksnark_verification_key<ppT> vk, boost::filesystem::path vk_path);
template<typename ppT> libsnark::r1cs_ppzksnark_verification_key<ppT> deserializeVerificationKeyFromFile(boost::filesystem::path vk_path);

template<typename ppT> void exportVerificationKey(libsnark::r1cs_ppzksnark_keypair<ppT> keypair);
template<typename ppT> void display_proof(libsnark::r1cs_ppzksnark_proof<ppT> proof);
template<typename ppT> void verificationKey_to_json(libsnark::r1cs_ppzksnark_keypair<ppT> keypair, boost::filesystem::path path = "");
template<typename ppT> void proof_to_json(libsnark::r1cs_ppzksnark_proof<ppT> proof, boost::filesystem::path path = "");
template<typename ppT> void write_setup(libsnark::r1cs_ppzksnark_keypair<ppT> keypair, boost::filesystem::path setup_dir = "");

template<typename ppT> void r1cs_constraints_to_json(libsnark::linear_combination<libff::Fr<ppT> > constraints, boost::filesystem::path path = "");
template<typename ppT> void fill_json_constraints_in_ss(libsnark::linear_combination<libff::Fr<ppT> > constraints, std::stringstream& ss);
template<typename ppT> void array_to_json(libsnark::protoboard<libff::Fr<ppT> > pb, uint input_variables, boost::filesystem::path path = "");
template<typename ppT> void r1cs_to_json(libsnark::protoboard<libff::Fr<ppT> > pb, uint input_variables, boost::filesystem::path path = "");
template<typename ppT> void proof_and_input_to_json(libsnark::r1cs_ppzksnark_proof<ppT> proof, libsnark::r1cs_ppzksnark_primary_input<ppT> input, boost::filesystem::path path = "");
template<typename ppT> void primary_input_to_json(libsnark::r1cs_ppzksnark_primary_input<ppT> input, boost::filesystem::path path = "");

// Display
template<typename ppT> void display_primary_input(libsnark::r1cs_ppzksnark_primary_input<ppT> input);

} // libzeth
#include "libsnark_helpers/libsnark_helpers.tcc"

#endif
