#ifndef __ZETH_COMPUTATION_HPP__
#define __ZETH_COMPUTATION_HPP__

#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

#include "libsnark_helpers/extended_proof.hpp"

// We instantiate the ppT (public parameters Template with the public paramaters of the curve we use (alt_bn128))
typedef libff::default_ec_pp ppT; // We use the public parameters of the alt_bn_128 curve to do our operations

namespace libzeth {

template<typename ppT>
extended_proof<ppT> gen_proof(libsnark::protoboard<libff::Fr<ppT> > pb, provingKeyT<ppT> proving_key);

template<typename ppT>
libsnark::r1cs_ppzksnark_keypair<ppT> gen_trusted_setup(libsnark::protoboard<libff::Fr<ppT> > pb);


} // libzeth
#include "circuits/computation.tcc"

#endif // __ZETH_COMPUTATION_HPP__
