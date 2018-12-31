/**
 * This file is modified from:
 *
 * @file wraplibsnark.hpp
 * @author Jacob Eberhardt <jacob.eberhardt@tu-berlin.de
 * @author Dennis Kuhnert <dennis.kuhnert@campus.tu-berlin.de>
 * @date 2017
 */

#ifndef __LIBSNARK_HELPERS_HPP__
#define __LIBSNARK_HELPERS_HPP__

#include <stdbool.h>
#include <stdint.h>
#include <fstream>
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

typedef libff::default_ec_pp ppT;

// -- Defined in the CPP file -- //
libff::bigint<libff::alt_bn128_r_limbs> libsnarkBigintFromBytes(const uint8_t* _x);
std::string HexStringFromLibsnarkBigint(libff::bigint<libff::alt_bn128_r_limbs> _x);
std::string outputPointG1AffineAsHex(libff::alt_bn128_G1 _p);
std::string outputPointG2AffineAsHex(libff::alt_bn128_G2 _p);

boost::filesystem::path getPathToSetupDir();
boost::filesystem::path getPathToDebugDir();

void serializeProvingKeyToFile(libsnark::r1cs_ppzksnark_proving_key<ppT> pk, boost::filesystem::path pk_path);
libsnark::r1cs_ppzksnark_proving_key<ppT> deserializeProvingKeyFromFile(boost::filesystem::path pk_path);
void serializeVerificationKeyToFile(libsnark::r1cs_ppzksnark_verification_key<ppT> vk, boost::filesystem::path vk_path);
libsnark::r1cs_ppzksnark_verification_key<ppT> deserializeVerificationKeyFromFile(boost::filesystem::path vk_path);

void exportVerificationKey(libsnark::r1cs_ppzksnark_keypair<ppT> keypair);
void display_proof(libsnark::r1cs_ppzksnark_proof<ppT> proof);
void verificationKey_to_json(libsnark::r1cs_ppzksnark_keypair<ppT> keypair, boost::filesystem::path path = "");
void proof_to_json(libsnark::r1cs_ppzksnark_proof<ppT> proof, boost::filesystem::path path = "");
void write_setup(libsnark::r1cs_ppzksnark_keypair<ppT> keypair, boost::filesystem::path setup_dir = "");

bool replace(std::string& str, const std::string& from, const std::string& to);

// -- Defined in the TCC file -- //
template<typename T> void writeToFile(boost::filesystem::path path, T& obj);
template<typename T> T loadFromFile(boost::filesystem::path path);

template<typename ppT> void constraint_to_json(libsnark::linear_combination<libff::Fr<ppT> > constraints, boost::filesystem::path path = "");
template<typename ppT> void array_to_json(libsnark::protoboard<libff::Fr<ppT> > pb, uint input_variables, boost::filesystem::path path = "");
template<typename ppT> void r1cs_to_json(libsnark::protoboard<libff::Fr<ppT> > pb, uint input_variables, boost::filesystem::path path = "");
template<typename ppT> void proof_and_input_to_json(libsnark::r1cs_ppzksnark_proof<ppT> proof, libsnark::r1cs_ppzksnark_primary_input<ppT> input, boost::filesystem::path path = "");
template<typename ppT> void primary_input_to_json(libsnark::r1cs_ppzksnark_primary_input<ppT> input, boost::filesystem::path path = "");

// Display
template<typename ppT> void display_primary_input(libsnark::r1cs_ppzksnark_primary_input<ppT> input);

// Include the template file
#include "libsnark_helpers.tcc"

#endif
