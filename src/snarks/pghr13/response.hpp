#ifndef __ZETH_RESPONSE_HPP__
#define __ZETH_RESPONSE_HPP__

#include "api/prover.grpc.pb.h"
#include "libsnark_helpers/extended_proof.hpp"
#include "util_api.hpp"

namespace libzeth
{

template<typename ppT>
void prepare_proof_response(
    extended_proof<ppT> &ext_proof, ExtendedProof *message);
template<typename ppT>
void prepare_verification_key_response(
    libsnark::r1cs_ppzksnark_verification_key<ppT> &vk,
    VerificationKey *message);

} // namespace libzeth
#include "snarks/pghr13/response.tcc"

#endif // __ZETH_RESPONSE_HPP__
