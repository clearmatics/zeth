// Copyright (c) 2015-2019 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_RESPONSE_TCC__
#define __ZETH_RESPONSE_TCC__

namespace libzeth
{

template<typename ppT>
void prepare_proof_response(
    extended_proof<ppT> &ext_proof, prover_proto::ExtendedProof *message)
{
    libsnark::r1cs_gg_ppzksnark_proof<ppT> proof_obj = ext_proof.get_proof();

    prover_proto::HexPointBaseGroup1Affine *a =
        new prover_proto::HexPointBaseGroup1Affine();
    prover_proto::HexPointBaseGroup2Affine *b =
        new prover_proto::HexPointBaseGroup2Affine(); // in G2
    prover_proto::HexPointBaseGroup1Affine *c =
        new prover_proto::HexPointBaseGroup1Affine();

    a->CopyFrom(format_hexPointBaseGroup1Affine(proof_obj.g_A));
    b->CopyFrom(format_hexPointBaseGroup2Affine(proof_obj.g_B)); // in G2
    c->CopyFrom(format_hexPointBaseGroup1Affine(proof_obj.g_C));

    libsnark::r1cs_ppzksnark_primary_input<ppT> public_inputs =
        ext_proof.get_primary_input();
    std::stringstream ss;
    ss << "[";
    for (size_t i = 0; i < public_inputs.size(); ++i) {
        ss << "\"0x" << hex_from_libsnark_bigint(public_inputs[i].as_bigint())
           << "\"";
        if (i < public_inputs.size() - 1) {
            ss << ", ";
        }
    }
    ss << "]";
    std::string inputs_json_str = ss.str();

    // Note on memory safety: set_allocated deleted the allocated objects
    // See:
    // https://stackoverflow.com/questions/33960999/protobuf-will-set-allocated-delete-the-allocated-object
    prover_proto::ExtendedProofGROTH16 *grpc_extended_groth16_proof_obj =
        message->mutable_groth16_extended_proof();

    grpc_extended_groth16_proof_obj->set_allocated_a(a);
    grpc_extended_groth16_proof_obj->set_allocated_b(b);
    grpc_extended_groth16_proof_obj->set_allocated_c(c);
    grpc_extended_groth16_proof_obj->set_inputs(inputs_json_str);
}

template<typename ppT>
void prepare_verification_key_response(
    libsnark::r1cs_gg_ppzksnark_verification_key<ppT> &vk,
    prover_proto::VerificationKey *message)
{
    prover_proto::HexPointBaseGroup1Affine *a =
        new prover_proto::HexPointBaseGroup1Affine(); // in G1
    prover_proto::HexPointBaseGroup2Affine *b =
        new prover_proto::HexPointBaseGroup2Affine(); // in G2
    prover_proto::HexPointBaseGroup2Affine *d =
        new prover_proto::HexPointBaseGroup2Affine(); // in G2

    a->CopyFrom(format_hexPointBaseGroup1Affine(vk.alpha_g1)); // in G1
    b->CopyFrom(format_hexPointBaseGroup2Affine(vk.beta_g2));  // in G2
    d->CopyFrom(format_hexPointBaseGroup2Affine(vk.delta_g2)); // in G2

    std::stringstream ss;
    unsigned abc_length = vk.ABC_g1.rest.indices.size() + 1;
    ss << "[[" << point_g1_affine_as_hex(vk.ABC_g1.first) << "]";
    for (size_t i = 1; i < abc_length; ++i) {
        auto vk_abc_i = point_g1_affine_as_hex(vk.ABC_g1.rest.values[i - 1]);
        ss << ",[" << vk_abc_i << "]";
    }
    ss << "]";
    std::string abc_json_str = ss.str();

    // Note on memory safety: set_allocated deleted the allocated objects
    // See:
    // https://stackoverflow.com/questions/33960999/protobuf-will-set-allocated-delete-the-allocated-object
    prover_proto::VerificationKeyGROTH16 *grpc_verification_key_groth16 =
        message->mutable_groth16_verification_key();

    grpc_verification_key_groth16->set_allocated_alpha_g1(a);
    grpc_verification_key_groth16->set_allocated_beta_g2(b);
    grpc_verification_key_groth16->set_allocated_delta_g2(d);
    grpc_verification_key_groth16->set_abc_g1(abc_json_str);
};

} // namespace libzeth

#endif // __ZETH_RESPONSE_TCC__
