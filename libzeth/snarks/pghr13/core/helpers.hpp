// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_HELPERS_HPP__
#define __ZETH_HELPERS_HPP__

#include "libzeth/libsnark_helpers/debug_helpers.hpp"

#include <boost/filesystem.hpp>
#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

namespace libzeth
{

template<typename ppT>
void export_verification_key(libsnark::r1cs_ppzksnark_keypair<ppT> keypair);
template<typename ppT>
void display_proof(libsnark::r1cs_ppzksnark_proof<ppT> proof);
template<typename ppT>
void verification_key_to_json(
    libsnark::r1cs_ppzksnark_keypair<ppT> keypair,
    boost::filesystem::path path = "");
template<typename ppT>
void proof_and_inputs_to_json(
    libsnark::r1cs_ppzksnark_proof<ppT> proof,
    libsnark::r1cs_ppzksnark_primary_input<ppT> input,
    boost::filesystem::path path = "");
template<typename ppT>
void proof_to_json(
    libsnark::r1cs_ppzksnark_proof<ppT> proof, boost::filesystem::path path);

} // namespace libzeth
#include "libzeth/snarks/pghr13/core/helpers.tcc"

#endif // __ZETH_HELPERS_HPP__
