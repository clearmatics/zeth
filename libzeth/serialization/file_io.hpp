// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SERIALIZATION_FILE_IO_HPP__
#define __ZETH_SERIALIZATION_FILE_IO_HPP__

#include "libzeth/types/extended_proof.hpp"
#include "libzeth/zeth.h"

#include <boost/filesystem.hpp>
#include <cassert>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdbool.h>
#include <stdint.h>

namespace libzeth
{

template<typename serializableT>
void write_to_file(boost::filesystem::path path, serializableT &obj);

template<typename serializableT>
serializableT load_from_file(boost::filesystem::path path);

template<typename snarkT>
void serialize_proving_key_to_file(
    const typename snarkT::ProvingKeyT &pk, boost::filesystem::path pk_path);

template<typename snarkT>
typename snarkT::ProvingKeyT deserialize_proving_key_from_file(
    boost::filesystem::path pk_path);

template<typename snarkT>
void serialize_verification_key_to_file(
    const typename snarkT::VerifKeyT &vk, boost::filesystem::path vk_path);

template<typename snarkT>
typename snarkT::VerifKeyT deserialize_verification_key_from_file(
    boost::filesystem::path vk_path);

template<typename snarkT>
void serialize_setup_to_file(
    const typename snarkT::KeypairT &keypair,
    boost::filesystem::path setup_path = "");

template<typename ppT>
void fill_stringstream_with_json_constraints(
    libsnark::linear_combination<libff::Fr<ppT>> constraints,
    std::stringstream &ss);

template<typename ppT>
void r1cs_to_json(
    libsnark::protoboard<libff::Fr<ppT>> pb,
    boost::filesystem::path r1cs_path = "");

} // namespace libzeth
#include "libzeth/serialization/file_io.tcc"

#endif // __ZETH_SERIALIZATION_FILE_IO_HPP__
