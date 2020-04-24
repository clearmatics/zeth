// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SNARKS_ALIAS_HPP__
#define __ZETH_SNARKS_ALIAS_HPP__

#if defined(ZKSNARK_PGHR13)
#define LIBZETH_SNARK_DEFINED
#include "libsnark/snarks/pghr13/core.hpp"
namespace libzeth
{
template<typename ppT> using defaultSnark = pghr13snark<ppT>;
} // namespace libzeth

xo // #include
// <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
// namespace libzeth
// {
// template<typename ppT>
// using ProvingKeyT = libsnark::r1cs_ppzksnark_proving_key<ppT>;
// templatep<typename ppT>
// using VerifKeyT = libsnark::r1cs_ppzksnark_verification_key<ppT>;
// template<typename ppT> using ProofT = libsnark::r1cs_ppzksnark_proof<ppT>;
// template<typename ppT> using KeypairT =
// libsnark::r1cs_ppzksnark_keypair<ppT>; } // namespace libzeth

#elif defined(ZKSNARK_GROTH16)
#define LIBZETH_SNARK_DEFINED
#include "libzeth/snarks/groth16/core.hpp"
namespace libzeth
{
template<typename ppT> using defaultSnark = groth16snark<ppT>;
} // namespace libzeth
  // #include
// <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
// namespace libzeth
// {
// template<typename ppT>
// using ProvingKeyT = libsnark::r1cs_gg_ppzksnark_proving_key<ppT>;
// template<typename ppT>
// using VerifKeyT = libsnark::r1cs_gg_ppzksnark_verification_key<ppT>;
// template<typename ppT> using ProofT = libsnark::r1cs_gg_ppzksnark_proof<ppT>;
// template<typename ppT>
// using KeypairT = libsnark::r1cs_gg_ppzksnark_keypair<ppT>;
// } // namespace libzeth

#else
#error You must define one of the SNARK_* symbols indicated into the CMakelists.txt file.
#endif

#endif // __ZETH_SNARKS_ALIAS_HPP__
