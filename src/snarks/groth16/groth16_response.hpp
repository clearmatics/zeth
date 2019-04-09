#ifndef __ZETH_GROTH16_RESPONSE_HPP__
#define __ZETH_GROTH16_RESPONSE_HPP__

#include "libsnark_helpers/extended_proof.hpp"

#include "prover.grpc.pb.h"
#include "util_api.hpp"


using proverpkg::VerificationKey;
using proverpkg::ExtendedProof;
using proverpkg::R1csGgPpzksnarkExtendedProof;
using proverpkg::R1csGgPpzksnarkVerificationKey;
using proverpkg::HexadecimalPointBaseGroup1Affine;
using proverpkg::HexadecimalPointBaseGroup2Affine;
using proverpkg::HexadecimalPointBaseGroupT;

namespace libzeth{

    template<typename ppT>
    void PrepareProofResponse(extended_proof<ppT>& ext_proof, ExtendedProof* message);
    
    template<typename ppT>
    void PrepareVerifyingKeyResponse(libsnark::r1cs_gg_ppzksnark_verification_key<ppT>& vk, VerificationKey* message);
    
}

#include "groth16_response.tcc"
#endif