#ifndef __ZETH_RESPONSE_HPP__
#define __ZETH_RESPONSE_HPP__

#include "api/prover.grpc.pb.h"
#include "libsnark_helpers/extended_proof.hpp"
#include "util_api.hpp"

namespace libzeth
{

template<typename ppT>
void prepare_proof_response(
    extended_proof<ppT> &ext_proof, prover_proto::ExtendedProof *message);
template<typename ppT>
void prepare_verification_key_response(
    libsnark::r1cs_gg_ppzksnark_verification_key<ppT> &vk,
    prover_proto::VerificationKey *message);

} // namespace libzeth
#include "snarks/groth16/response.tcc"

#endif // __ZETH_RESPONSE_HPP__
