#ifndef __ZETH_SNARKS_ALIAS_HPP__
#define __ZETH_SNARKS_ALIAS_HPP__

/************************ Pick a zkSNARK ****************************/

#ifdef SNARK_R1CS_PPZKSNARK
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

#ifdef SNARK_R1CS_GG_PPZKSNARK
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
