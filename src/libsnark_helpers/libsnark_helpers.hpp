// DISCLAIMER:
// Content taken and adapted from:
// wraplibsnark.cpp (originally written by Jacob Eberhardt and Dennis Kuhnert)

#ifndef __LIBSNARK_HELPERS_HPP__
#define __LIBSNARK_HELPERS_HPP__

#include <boost/filesystem.hpp>
#include <cassert>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdbool.h>
#include <stdint.h>

// Contains definition of alt_bn128 ec public parameters
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/common/default_types/ec_pp.hpp>
#include <libsnark/gadgetlib1/gadget.hpp>
// Contains required interfaces and types (keypair, proof, generator, prover,
// verifier)
#include "extended_proof.hpp"
#include "snarks_alias.hpp"
#include "snarks_core_imports.hpp"
#include "zeth.h"

namespace libzeth
{

template<typename serializableT>
void writeToFile(boost::filesystem::path path, serializableT &obj);
template<typename serializableT>
serializableT loadFromFile(boost::filesystem::path path);

template<typename ppT>
void serializeProvingKeyToFile(
    provingKeyT<ppT> &pk, boost::filesystem::path pk_path);
template<typename ppT>
provingKeyT<ppT> deserializeProvingKeyFromFile(boost::filesystem::path pk_path);
template<typename ppT>
void serializeVerificationKeyToFile(
    verificationKeyT<ppT> &vk, boost::filesystem::path vk_path);
template<typename ppT>
verificationKeyT<ppT> deserializeVerificationKeyFromFile(
    boost::filesystem::path vk_path);

template<typename ppT>
void writeSetup(keyPairT<ppT> keypair, boost::filesystem::path setup_dir = "");

template<typename ppT>
void r1csConstraintsToJson(
    libsnark::linear_combination<libff::Fr<ppT>> constraints,
    boost::filesystem::path path = "");
template<typename ppT>
void fillJsonConstraintsInSs(
    libsnark::linear_combination<libff::Fr<ppT>> constraints,
    std::stringstream &ss);
template<typename ppT>
void arrayToJson(
    libsnark::protoboard<libff::Fr<ppT>> pb,
    uint input_variables,
    boost::filesystem::path path = "");
template<typename ppT>
void r1csToJson(
    libsnark::protoboard<libff::Fr<ppT>> pb,
    uint input_variables,
    boost::filesystem::path path = "");
template<typename ppT>
void primaryInputToJson(
    libsnark::r1cs_primary_input<libff::Fr<ppT>> input,
    boost::filesystem::path = "");

} // namespace libzeth
#include "libsnark_helpers/libsnark_helpers.tcc"

#endif
