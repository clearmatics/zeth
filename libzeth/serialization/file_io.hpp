// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SERIALIZATION_FILE_IO_HPP__
#define __ZETH_SERIALIZATION_FILE_IO_HPP__

#include "libzeth/libsnark_helpers/debug_helpers.hpp"

#include <boost/filesystem.hpp>
#include <cassert>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <libff/common/default_types/ec_pp.hpp>
#include <libsnark/gadgetlib1/gadget.hpp>
#include <sstream>
#include <stdbool.h>
#include <stdint.h>

// Contains required interfaces and types (keypair, proof, generator, prover,
// verifier)
#include "libzeth/libsnark_helpers/extended_proof.hpp"
#include "libzeth/snarks_alias.hpp"
#include "libzeth/snarks_core_imports.hpp"
#include "libzeth/zeth.h"

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
void serialize_setup_to_file(keyPairT<ppT> keypair, boost::filesystem::path setup_path = "");

template<typename ppT>
void fill_stringstream_with_json_constraints(
    libsnark::linear_combination<libff::Fr<ppT>> constraints,
    std::stringstream &ss);

template<typename ppT>
void r1cs_to_json(
    libsnark::protoboard<libff::Fr<ppT>> pb, boost::filesystem::path r1cs_path = "");

} // namespace libzeth
#include "libzeth/serialization/file_io.tcc"

#endif // __ZETH_SERIALIZATION_FILE_IO_HPP__
