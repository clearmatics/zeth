// DISCLAIMER:
// Content taken and adapted from:
// wraplibsnark.cpp (originally written by Jacob Eberhardt and Dennis Kuhnert)

#ifndef __LIBSNARK_HELPERS_HPP__
#define __LIBSNARK_HELPERS_HPP__

#include "libsnark_helpers/debug_helpers.hpp"

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
void write_to_file(boost::filesystem::path path, serializableT &obj);
template<typename serializableT>
serializableT load_from_file(boost::filesystem::path path);

template<typename ppT>
void serialize_proving_key_to_file(
    provingKeyT<ppT> &pk, boost::filesystem::path pk_path);
template<typename ppT>
provingKeyT<ppT> deserialize_proving_key_from_file(
    boost::filesystem::path pk_path);
template<typename ppT>
void serialize_verification_key_to_file(
    verificationKeyT<ppT> &vk, boost::filesystem::path vk_path);
template<typename ppT>
verificationKeyT<ppT> deserialize_verification_key_from_file(
    boost::filesystem::path vk_path);

template<typename ppT>
void write_setup(keyPairT<ppT> keypair, boost::filesystem::path setup_dir = "");

template<typename ppT>
void fill_stringstream_with_json_constraints(
    libsnark::linear_combination<libff::Fr<ppT>> constraints,
    std::stringstream &ss);
template<typename ppT>
void r1cs_to_json(
    libsnark::protoboard<libff::Fr<ppT>> pb, boost::filesystem::path path = "");

} // namespace libzeth
#include "libsnark_helpers/libsnark_helpers.tcc"

#endif
