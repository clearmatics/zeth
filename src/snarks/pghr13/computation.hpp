#ifndef __ZETH_COMPUTATION_HPP__
#define __ZETH_COMPUTATION_HPP__

#include "libsnark_helpers/extended_proof.hpp"

#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

// We instantiate the ppT (public parameters Template with the public paramaters
// of the curve we use (alt_bn128))
typedef libff::default_ec_pp ppT;

namespace libzeth
{

template<typename ppT>
libsnark::r1cs_ppzksnark_proof<ppT> gen_proof(
    libsnark::protoboard<libff::Fr<ppT>> pb,
    libsnark::r1cs_ppzksnark_proving_key<ppT> proving_key);
template<typename ppT>
libsnark::r1cs_ppzksnark_keypair<ppT> gen_trusted_setup(
    libsnark::protoboard<libff::Fr<ppT>> pb);
template<typename ppT>
bool verify(
    libzeth::extended_proof<ppT> ext_proof,
    libsnark::r1cs_ppzksnark_verification_key<ppT> verification_key);

} // namespace libzeth
#include "snarks/pghr13/computation.tcc"

#endif // __ZETH_COMPUTATION_HPP__
