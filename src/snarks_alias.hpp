#ifndef __ZETH_SNARKS_ALIAS_HPP__
#define __ZETH_SNARKS_ALIAS_HPP__

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libsnark/gadgetlib1/protoboard.hpp>
#include <libsnark/gadgetlib1/gadget.hpp>

namespace libzeth {

//typedef libff::bigint<libff::alt_bn128_r_limbs> LimbT;
//typedef libff::alt_bn128_G1 G1T;
//typedef libff::alt_bn128_G2 G2T;
typedef libff::alt_bn128_pp ppT;
//typedef libff::Fq<ppT> FqT;
typedef libff::Fr<ppT> FieldT;
typedef libsnark::r1cs_constraint<FieldT> ConstraintT;
typedef libsnark::protoboard<FieldT> ProtoboardT;
typedef libsnark::pb_variable<libzeth::FieldT> VariableT;
typedef libsnark::pb_variable_array<FieldT> VariableArrayT;
typedef libsnark::pb_linear_combination<FieldT> LinearCombinationT;
typedef libsnark::pb_linear_combination_array<FieldT> LinearCombinationArrayT;
typedef libsnark::linear_term<FieldT> LinearTermT;
typedef libsnark::gadget<libzeth::FieldT> GadgetT;

}

/************************ Pick a zkSNARK ****************************/

#ifdef ZKSNARK_PGHR13
#define LIBZETH_SNARK_DEFINED
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
namespace libzeth {
template<typename ppT>
using provingKeyT = libsnark::r1cs_ppzksnark_proving_key<ppT>;
template<typename ppT>
using verificationKeyT = libsnark::r1cs_ppzksnark_verification_key<ppT>;
template<typename ppT>
using proofT = libsnark::r1cs_ppzksnark_proof<ppT>;
template<typename ppT>
using keyPairT = libsnark::r1cs_ppzksnark_keypair<ppT>;
} // libzeth
#endif

#ifdef ZKSNARK_GROTH16
#define LIBZETH_SNARK_DEFINED
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
namespace libzeth {
template<typename ppT>
using provingKeyT = libsnark::r1cs_gg_ppzksnark_proving_key<ppT>;
template<typename ppT>
using verificationKeyT = libsnark::r1cs_gg_ppzksnark_verification_key<ppT>;
template<typename ppT>
using proofT = libsnark::r1cs_gg_ppzksnark_proof<ppT>;
template<typename ppT>
using keyPairT = libsnark::r1cs_gg_ppzksnark_keypair<ppT>;
} // libzeth
#endif

#ifndef LIBZETH_SNARK_DEFINED
#error You must define one of the SNARK_* symbols indicated into the CMakelists.txt file.
#endif

#endif // __ZETH_SNARKS_ALIAS_HPP__
