// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SNARKS_CORE_HELPERS_HPP__
#define __ZETH_SNARKS_CORE_HELPERS_HPP__

#include "libzeth/serialization/filesystem_util.hpp"
#include "libzeth/sciprlab_libs_util.hpp"

#include <boost/filesystem.hpp>
#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

namespace libzeth
{

// /// Check proving key entries
// template<typename ppT>
// bool is_well_formed<libsnark::r1cs_ppzksnark_proving_key<ppT>>(
//     const libsnark::r1cs_ppzksnark_proving_key<ppT> &pk);

// /// Check verification key entries
// template<typename ppT>
// bool is_well_formed(
//     const libsnark::r1cs_gg_ppzksnark_verification_key<ppT> &vk);

template<typename ppT>
void export_verification_key(libsnark::r1cs_gg_ppzksnark_keypair<ppT> keypair);

template<typename ppT>
void display_proof(libsnark::r1cs_gg_ppzksnark_proof<ppT> proof);

template<typename ppT>
void verification_key_to_json(
    libsnark::r1cs_gg_ppzksnark_keypair<ppT> keypair,
    boost::filesystem::path path = "");

template<typename ppT>
void proof_and_inputs_to_json(
    libsnark::r1cs_gg_ppzksnark_proof<ppT> proof,
    libsnark::r1cs_primary_input<ppT> input,
    boost::filesystem::path path = "");

template<typename ppT>
void proof_to_json(
    libsnark::r1cs_gg_ppzksnark_proof<ppT> proof, boost::filesystem::path path);

} // namespace libzeth
#include "libzeth/snarks/groth16/core/helpers.tcc"

#endif // __ZETH_SNARKS_CORE_HELPERS_HPP__
