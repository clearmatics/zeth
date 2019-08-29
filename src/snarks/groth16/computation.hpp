#ifndef __ZETH_COMPUTATION_HPP__
#define __ZETH_COMPUTATION_HPP__

#include "libsnark_helpers/debug_helpers.hpp"
#include "libsnark_helpers/extended_proof.hpp"

#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

namespace libzeth
{

template<typename ppT>
libsnark::r1cs_gg_ppzksnark_proof<ppT> gen_proof(
    const libsnark::protoboard<libff::Fr<ppT>> &pb,
    const libsnark::r1cs_gg_ppzksnark_proving_key<ppT> &proving_key);

template<typename ppT>
libsnark::r1cs_gg_ppzksnark_keypair<ppT> gen_trusted_setup(
    const libsnark::protoboard<libff::Fr<ppT>> &pb);

template<typename ppT>
bool verify(
    const libzeth::extended_proof<ppT> &ext_proof,
    const libsnark::r1cs_gg_ppzksnark_verification_key<ppT> &verification_key);

} // namespace libzeth

#include "snarks/groth16/computation.tcc"

#endif // __ZETH_COMPUTATION_HPP__
