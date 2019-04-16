#ifndef __ZETH_GROTH16_COMPUTATION_HPP__
#define __ZETH_GROTH16_COMPUTATION_HPP__

#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/gadgetlib1/gadget.hpp>
#include "libsnark_helpers/extended_proof.hpp"
#include "libsnark_helpers/debug_helpers.hpp"

typedef libff::default_ec_pp ppT; // We use the public parameters of the alt_bn_128 curve to do our operations

namespace libzeth {

    // circuit-wrapper functions
    template<typename ppT>
    libsnark::r1cs_gg_ppzksnark_proof<ppT> gen_proof(libsnark::protoboard<libff::Fr<ppT> > pb, libsnark::r1cs_gg_ppzksnark_proving_key<ppT> proving_key);

    template<typename ppT>
    libsnark::r1cs_gg_ppzksnark_keypair<ppT> gen_trusted_setup (libsnark::protoboard<libff::Fr<ppT> > pb);

} // libzeth
#include "snarks/groth16/computation.tcc"

#endif // __ZETH_GROTH16_COMPUTATION_HPP__