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

// Contains required interfaces and types (keypair, proof, generator, prover, verifier)
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/gadgetlib1/gadget.hpp>

libff::bigint<libff::alt_bn128_r_limbs> libsnarkBigintFromBytes(const uint8_t* _x);
std::string HexStringFromLibsnarkBigint(libff::bigint<libff::alt_bn128_r_limbs> _x);
std::string outputPointG1AffineAsHex(libff::alt_bn128_G1 _p);
std::string outputPointG2AffineAsHex(libff::alt_bn128_G2 _p);

// Generate key pair from constraints
libsnark::r1cs_ppzksnark_keypair<libff::alt_bn128_pp> generateKeypair(const libsnark::r1cs_ppzksnark_constraint_system<libff::alt_bn128_pp> &cs);

// Write to and load from files
template<typename T> void writeToFile(std::string path, T& obj);
template<typename T> T loadFromFile(std::string path);

// Return the path to the setup directory from environment variable
boost::filesystem::path getPathToSetupDir();

// Serialization/Deserialization of keys in raw format (write to/load from specified files)
void serializeProvingKeyToFile(libsnark::r1cs_ppzksnark_proving_key<libff::alt_bn128_pp> pk, const char* pk_path);
libsnark::r1cs_ppzksnark_proving_key<libff::alt_bn128_pp> deserializeProvingKeyFromFile(const char* pk_path);
void serializeVerificationKeyToFile(libsnark::r1cs_ppzksnark_verification_key<libff::alt_bn128_pp> vk, const char* vk_path);
libsnark::r1cs_ppzksnark_verification_key<libff::alt_bn128_pp> deserializeVerificationKeyFromFile(const char* vk_path);

void exportVerificationKey(libsnark::r1cs_ppzksnark_keypair<libff::alt_bn128_pp> keypair);
template<typename FieldT> void exportInput(libsnark::r1cs_primary_input<FieldT> input);
void printProof(libsnark::r1cs_ppzksnark_proof<libff::alt_bn128_pp> proof);

// Export to json format
void verificationKey_to_json(libsnark::r1cs_ppzksnark_keypair<libff::alt_bn128_pp> keypair, std::string path);
template<typename FieldT> void proof_to_json(libsnark::r1cs_ppzksnark_proof<libff::alt_bn128_pp> proof, libsnark::r1cs_primary_input<FieldT> input);
template<typename FieldT> void r1cs_to_json(libsnark::protoboard<FieldT> pb, uint input_variables, std::string path);
template<typename FieldT> void array_to_json(libsnark::protoboard<FieldT> pb, uint input_variables, std::string path);
template<typename FieldT> void constraint_to_json(libsnark::linear_combination<FieldT> constraints, std::string path);

bool replace(std::string& str, const std::string& from, const std::string& to);

// Include the template file
#include "libsnark_helpers.tcc"

#endif
