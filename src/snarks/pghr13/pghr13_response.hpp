#include "libsnark_helpers/extended_proof.hpp"

#include "prover.grpc.pb.h"

using proverpkg::VerificationKey;
using proverpkg::ExtendedProof;
using proverpkg::R1csPpzksnarkExtendedProof;
using proverpkg::R1csPpzksnarkVerificationKey;
using proverpkg::HexadecimalPointBaseGroup1Affine;
using proverpkg::HexadecimalPointBaseGroup2Affine;

typedef libff::default_ec_pp ppT;

namespace libzeth{
    HexadecimalPointBaseGroup1Affine FormatHexadecimalPointBaseGroup1Affine(libff::alt_bn128_G1 point);
    HexadecimalPointBaseGroup2Affine FormatHexadecimalPointBaseGroup2Affine(libff::alt_bn128_G2 point);
    void PrepareProofResponse(extended_proof<ppT>& ext_proof, ExtendedProof* message);
    void PrepareVerifyingKeyResponse(libsnark::r1cs_ppzksnark_verification_key<ppT>& vk, VerificationKey* message);
}
