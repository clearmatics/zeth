#ifndef __ZETH_CONSTANTS__
#define __ZETH_CONSTANTS__

#define ZETH_NUM_JS_INPUTS 2
#define ZETH_NUM_JS_OUTPUTS 2

#define ZETH_MERKLE_TREE_DEPTH 4
#define ZETH_MERKLE_TREE_DEPTH_TEST 4

#define ZETH_V_SIZE 8 // 64 bits for the value
#define ZETH_RHO_SIZE 32 // 256 bits for rho
#define ZETH_A_SK_SIZE 32 // 256 bits for rho
#define ZETH_R_SIZE 48 // 384 bits for r

#define ZETH_DIGEST_BIT_SIZE 256 // Size of a sha256 digest in bits
#define ZETH_DIGEST_HEX_SIZE 64 // Size of a sha256 digest in hex characters

#endif // __ZETH_CONSTANTS__

#ifndef SNARK_HPP_
#define SNARK_HPP_

/************************ Pick a Snark ****************************/

#ifdef SNARK_R1CS_PPZKSNARK
#define LIBZETH_DEFAULT_SNARK_DEFINED
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>

namespace libzeth {
template<typename ppT>
using provingKeyT = libsnark::r1cs_ppzksnark_proving_key <ppT>;
template<typename ppT>
using verificationKeyT = libsnark::r1cs_ppzksnark_verification_key <ppT>;
template<typename ppT>
using proofT = libsnark::r1cs_ppzksnark_proof <ppT>;
template<typename ppT>
using keyPairT = libsnark::r1cs_ppzksnark_keypair <ppT>;

}

#endif

#ifdef SNARK_R1CS_GG_PPZKSNARK
#define LIBZETH_DEFAULT_SNARK_DEFINED
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_gg_ppzksnark.hpp>

namespace libzeth {
template<typename ppT>
using provingKeyT = libsnark::r1cs_gg_ppzksnark_proving_key <ppT>;
template<typename ppT>
using verificationKeyT = libsnark::r1cs_gg_ppzksnark_verification_key <ppT>;
template<typename ppT>
using proofT = libsnark::r1cs_gg_ppzksnark_proof <ppT>;
template<typename ppT>
using keyPairT = libsnark::r1cs_gg_ppzksnark_keypair <ppT>;
#define SNARK 2// TODO: review this define
}

#endif

#ifdef SNARK_R1CS_SE_PPZKSNARK
#define LIBZETH_DEFAULT_SNARK_DEFINED
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_se_ppzksnark.hpp>

namespace libzeth {
template<typename ppT>
using provingKeyT = libsnark::r1cs_se_ppzksnark_proving_key <ppT>;
template<typename ppT>
using verificationKeyT = libsnark::r1cs_se_ppzksnark_verification_key <ppT>;
template<typename ppT>
using proofT = libsnark::r1cs_se_ppzksnark_proof <ppT>;
template<typename ppT>
using keyPairT = libsnark::r1cs_se_ppzksnark_keypair <ppT>;
#define SNARK 3// TODO: review this define
}

#endif

#ifndef LIBZETH_DEFAULT_SNARK_DEFINED
#error You must define one of the SNARK_* symbols indicated into the cmake file.
#endif

#endif // SNARK_HPP_
