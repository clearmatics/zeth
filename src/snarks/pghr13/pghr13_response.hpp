#ifndef __ZETH_PGHR13_RESPONSE_HPP__
#define __ZETH_PGHR13_RESPONSE_HPP__

#include "libsnark_helpers/extended_proof.hpp"

#include "prover.grpc.pb.h"//TODO: check if is redundant
#include "util_api.hpp"


using proverpkg::VerificationKey;
using proverpkg::ExtendedProof;
using proverpkg::R1csPpzksnarkExtendedProof;
using proverpkg::R1csPpzksnarkVerificationKey;
using proverpkg::HexadecimalPointBaseGroup1Affine;
using proverpkg::HexadecimalPointBaseGroup2Affine;

namespace libzeth{

    template<typename ppT>
    void PrepareProofResponse(extended_proof<ppT>& ext_proof, ExtendedProof* message);
    template<typename ppT>
    void PrepareVerifyingKeyResponse(libsnark::r1cs_ppzksnark_verification_key<ppT>& vk, VerificationKey* message);
    
}

#include "pghr13_response.tcc"
#endif