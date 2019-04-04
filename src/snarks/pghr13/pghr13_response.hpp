#include "libsnark_helpers/extended_proof.hpp"

#include "prover.grpc.pb.h"
#include "util_api.hpp"


using proverpkg::VerificationKey;
using proverpkg::ExtendedProof;
using proverpkg::R1csPpzksnarkExtendedProof;
using proverpkg::R1csPpzksnarkVerificationKey;
using proverpkg::HexadecimalPointBaseGroup1Affine;
using proverpkg::HexadecimalPointBaseGroup2Affine;

typedef libff::default_ec_pp ppT;

namespace libzeth{
    void PrepareProofResponse(extended_proof<ppT>& ext_proof, ExtendedProof* message);
    void PrepareVerifyingKeyResponse(libsnark::r1cs_ppzksnark_verification_key<ppT>& vk, VerificationKey* message);
}
