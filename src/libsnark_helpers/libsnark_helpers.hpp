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
#include "snarks.hpp"

#include "extended_proof.hpp"

#ifdef SNARK_R1CS_PPZKSNARK
#include "snarks/pghr13/pghr13_response.hpp"
#include "snarks/pghr13/pghr13_computation.hpp"
#elif SNARK_R1CS_GG_PPZKSNARK
#include "groth16_response.hpp"
#include "snarks/groth16/groth16_computation.hpp"
#else
#error You must define one of the SNARK_* symbols indicated into the CMakelists.txt file.
#endif

namespace libzeth {
// -- Defined in the TCC file -- //TODO: here


//old
template<typename serializableT> void writeToFile(boost::filesystem::path path, serializableT& obj);
template<typename serializableT> serializableT loadFromFile(boost::filesystem::path path);

template<typename ppT> void serializeProvingKeyToFile(provingKeyT<ppT> &pk, boost::filesystem::path pk_path);
template<typename ppT> provingKeyT<ppT> deserializeProvingKeyFromFile(boost::filesystem::path pk_path);
template<typename ppT> void serializeVerificationKeyToFile(verificationKeyT<ppT> &vk, boost::filesystem::path vk_path);
template<typename ppT> verificationKeyT<ppT> deserializeVerificationKeyFromFile(boost::filesystem::path vk_path);

template<typename ppT> void writeSetup(keyPairT<ppT> keypair, boost::filesystem::path setup_dir = "");

template<typename ppT> void r1csConstraintsToJson(libsnark::linear_combination<libff::Fr<ppT> > constraints, boost::filesystem::path path = "");
template<typename ppT> void fillJsonConstraintsInSs(libsnark::linear_combination<libff::Fr<ppT> > constraints, std::stringstream& ss);
template<typename ppT> void arrayToJson(libsnark::protoboard<libff::Fr<ppT> > pb, uint input_variables, boost::filesystem::path path = "");
template<typename ppT> void r1csToJson(libsnark::protoboard<libff::Fr<ppT> > pb, uint input_variables, boost::filesystem::path path = "");


template<typename ppT> void primaryInputToJson(libsnark::r1cs_primary_input<libff::Fr<ppT>> input, boost::filesystem::path = "");

template<typename ppT> void write_proof(libzeth::proofT<ppT> proof, boost::filesystem::path path); //exported from extende proof
template<typename ppT> void write_extended_proof(libzeth::extended_proof<ppT> extended_proof, boost::filesystem::path path); //exported from extende proof
template<typename ppT> void dump_proof(proofT<ppT> proof); //exported from extende proof

} // libzeth
#include "libsnark_helpers/libsnark_helpers.tcc"

#endif
