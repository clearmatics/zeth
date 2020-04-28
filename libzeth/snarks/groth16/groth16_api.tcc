// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SNARKS_GROTH16_GROTH16_API_TCC__
#define __ZETH_SNARKS_GROTH16_GROTH16_API_TCC__

#include "libzeth/core/ff_utils.hpp"
#include "libzeth/serialization/api/api_io.hpp"
#include "libzeth/snarks/groth16/groth16_api.hpp"

namespace libzeth
{

template<typename ppT>
void groth16api<ppT>::format_extended_proof(
    const extended_proof<ppT, groth16api<ppT>::snarkT> &ext_proof,
    zeth_proto::ExtendedProof *message)
{
    libsnark::r1cs_gg_ppzksnark_proof<ppT> proof_obj = ext_proof.get_proof();

    zeth_proto::HexPointBaseGroup1Affine *a =
        new zeth_proto::HexPointBaseGroup1Affine();
    zeth_proto::HexPointBaseGroup2Affine *b =
        new zeth_proto::HexPointBaseGroup2Affine(); // in G2
    zeth_proto::HexPointBaseGroup1Affine *c =
        new zeth_proto::HexPointBaseGroup1Affine();

    a->CopyFrom(format_hexPointBaseGroup1Affine<ppT>(proof_obj.g_A));
    b->CopyFrom(format_hexPointBaseGroup2Affine<ppT>(proof_obj.g_B)); // in G2
    c->CopyFrom(format_hexPointBaseGroup1Affine<ppT>(proof_obj.g_C));

    libsnark::r1cs_gg_ppzksnark_primary_input<ppT> public_inputs =
        ext_proof.get_primary_inputs();

    std::string inputs_json_str =
        format_primary_inputs<ppT>(std::vector<libff::Fr<ppT>>(public_inputs));

    // Note on memory safety: set_allocated deleted the allocated objects. See:
    // https://stackoverflow.com/questions/33960999/protobuf-will-set-allocated-delete-the-allocated-object
    zeth_proto::ExtendedProofGROTH16 *grpc_extended_groth16_proof_obj =
        message->mutable_groth16_extended_proof();

    grpc_extended_groth16_proof_obj->set_allocated_a(a);
    grpc_extended_groth16_proof_obj->set_allocated_b(b);
    grpc_extended_groth16_proof_obj->set_allocated_c(c);
    grpc_extended_groth16_proof_obj->set_inputs(inputs_json_str);
}

template<typename ppT>
void groth16api<ppT>::format_verification_key(
    const typename groth16api<ppT>::snarkT::VerifKeyT &vk,
    zeth_proto::VerificationKey *message)
{
    zeth_proto::HexPointBaseGroup1Affine *a =
        new zeth_proto::HexPointBaseGroup1Affine(); // in G1
    zeth_proto::HexPointBaseGroup2Affine *b =
        new zeth_proto::HexPointBaseGroup2Affine(); // in G2
    zeth_proto::HexPointBaseGroup2Affine *d =
        new zeth_proto::HexPointBaseGroup2Affine(); // in G2

    a->CopyFrom(format_hexPointBaseGroup1Affine<ppT>(vk.alpha_g1)); // in G1
    b->CopyFrom(format_hexPointBaseGroup2Affine<ppT>(vk.beta_g2));  // in G2
    d->CopyFrom(format_hexPointBaseGroup2Affine<ppT>(vk.delta_g2)); // in G2

    std::stringstream ss;
    unsigned abc_length = vk.ABC_g1.rest.indices.size() + 1;
    ss << "[[" << point_g1_affine_to_hexadecimal_str<ppT>(vk.ABC_g1.first)
       << "]";
    for (size_t i = 1; i < abc_length; ++i) {
        auto vk_abc_i = point_g1_affine_to_hexadecimal_str<ppT>(
            vk.ABC_g1.rest.values[i - 1]);
        ss << ",[" << vk_abc_i << "]";
    }
    ss << "]";
    std::string abc_json_str = ss.str();

    // Note on memory safety: set_allocated deleted the allocated objects
    // See:
    // https://stackoverflow.com/questions/33960999/protobuf-will-set-allocated-delete-the-allocated-object
    zeth_proto::VerificationKeyGROTH16 *grpc_verification_key_groth16 =
        message->mutable_groth16_verification_key();

    grpc_verification_key_groth16->set_allocated_alpha_g1(a);
    grpc_verification_key_groth16->set_allocated_beta_g2(b);
    grpc_verification_key_groth16->set_allocated_delta_g2(d);
    grpc_verification_key_groth16->set_abc_g1(abc_json_str);
}

template<typename ppT>
libzeth::extended_proof<ppT, groth16snark<ppT>> groth16api<
    ppT>::parse_extended_proof(const zeth_proto::ExtendedProof &ext_proof)
{
    const zeth_proto::ExtendedProofGROTH16 &e_proof =
        ext_proof.groth16_extended_proof();
    // G1
    libff::G1<ppT> a = parse_hexPointBaseGroup1Affine<ppT>(e_proof.a());
    // G2
    libff::G2<ppT> b = parse_hexPointBaseGroup2Affine<ppT>(e_proof.b());
    // G1
    libff::G1<ppT> c = parse_hexPointBaseGroup1Affine<ppT>(e_proof.c());

    std::vector<libff::Fr<ppT>> inputs =
        libsnark::r1cs_primary_input<libff::Fr<ppT>>(
            parse_str_primary_inputs<ppT>(e_proof.inputs()));

    libsnark::r1cs_gg_ppzksnark_proof<ppT> proof(
        std::move(a), std::move(b), std::move(c));
    libzeth::extended_proof<ppT, groth16snark<ppT>> res(proof, inputs);

    return res;
}

template<typename ppT>
typename groth16snark<ppT>::VerifKeyT groth16api<ppT>::parse_verification_key(
    const zeth_proto::VerificationKey &verification_key)
{
    const zeth_proto::VerificationKeyGROTH16 &verif_key =
        verification_key.groth16_verification_key();
    // G1
    libff::G1<ppT> alpha_g1 =
        parse_hexPointBaseGroup1Affine<ppT>(verif_key.alpha_g1());
    // G2
    libff::G2<ppT> beta_g2 =
        parse_hexPointBaseGroup2Affine<ppT>(verif_key.beta_g2());
    // G2
    libff::G2<ppT> delta_g2 =
        parse_hexPointBaseGroup2Affine<ppT>(verif_key.delta_g2());

    libsnark::accumulation_vector<libff::G1<ppT>> abc_g1 =
        parse_str_accumulation_vector<ppT>(verif_key.abc_g1());

    libsnark::r1cs_gg_ppzksnark_verification_key<ppT> vk(
        alpha_g1, beta_g2, delta_g2, abc_g1);

    return vk;
}

template<typename ppT>
void groth16api<ppT>::prepare_proof_response(
    const extended_proof<ppT, snarkT> &ext_proof,
    zeth_proto::ExtendedProof *message)
{
    libsnark::r1cs_gg_ppzksnark_proof<ppT> proof_obj = ext_proof.get_proof();

    zeth_proto::HexPointBaseGroup1Affine *a =
        new zeth_proto::HexPointBaseGroup1Affine();
    zeth_proto::HexPointBaseGroup2Affine *b =
        new zeth_proto::HexPointBaseGroup2Affine(); // in G2
    zeth_proto::HexPointBaseGroup1Affine *c =
        new zeth_proto::HexPointBaseGroup1Affine();

    a->CopyFrom(format_hexPointBaseGroup1Affine<ppT>(proof_obj.g_A));
    b->CopyFrom(format_hexPointBaseGroup2Affine<ppT>(proof_obj.g_B)); // in G2
    c->CopyFrom(format_hexPointBaseGroup1Affine<ppT>(proof_obj.g_C));

    libsnark::r1cs_gg_ppzksnark_primary_input<ppT> public_inputs =
        ext_proof.get_primary_input();

    std::string inputs_json_str =
        format_primary_inputs<ppT>(std::vector<libff::Fr<ppT>>(public_inputs));

    // Note on memory safety: set_allocated deleted the allocated objects
    // See:
    // https://stackoverflow.com/questions/33960999/protobuf-will-set-allocated-delete-the-allocated-object
    zeth_proto::ExtendedProofGROTH16 *grpc_extended_groth16_proof_obj =
        message->mutable_groth16_extended_proof();

    grpc_extended_groth16_proof_obj->set_allocated_a(a);
    grpc_extended_groth16_proof_obj->set_allocated_b(b);
    grpc_extended_groth16_proof_obj->set_allocated_c(c);
    grpc_extended_groth16_proof_obj->set_inputs(inputs_json_str);
}

template<typename ppT>
void groth16api<ppT>::prepare_verification_key_response(
    const typename snarkT::VerifKeyT &vk, zeth_proto::VerificationKey *message)
{
    zeth_proto::HexPointBaseGroup1Affine *a =
        new zeth_proto::HexPointBaseGroup1Affine(); // in G1
    zeth_proto::HexPointBaseGroup2Affine *b =
        new zeth_proto::HexPointBaseGroup2Affine(); // in G2
    zeth_proto::HexPointBaseGroup2Affine *d =
        new zeth_proto::HexPointBaseGroup2Affine(); // in G2

    a->CopyFrom(format_hexPointBaseGroup1Affine<ppT>(vk.alpha_g1)); // in G1
    b->CopyFrom(format_hexPointBaseGroup2Affine<ppT>(vk.beta_g2));  // in G2
    d->CopyFrom(format_hexPointBaseGroup2Affine<ppT>(vk.delta_g2)); // in G2

    std::stringstream ss;
    unsigned abc_length = vk.ABC_g1.rest.indices.size() + 1;
    ss << "[[" << point_g1_affine_to_hexadecimal_str<ppT>(vk.ABC_g1.first)
       << "]";
    for (size_t i = 1; i < abc_length; ++i) {
        auto vk_abc_i = point_g1_affine_to_hexadecimal_str<ppT>(
            vk.ABC_g1.rest.values[i - 1]);
        ss << ",[" << vk_abc_i << "]";
    }
    ss << "]";
    std::string abc_json_str = ss.str();

    // Note on memory safety: set_allocated deleted the allocated objects
    // See:
    // https://stackoverflow.com/questions/33960999/protobuf-will-set-allocated-delete-the-allocated-object
    zeth_proto::VerificationKeyGROTH16 *grpc_verification_key_groth16 =
        message->mutable_groth16_verification_key();

    grpc_verification_key_groth16->set_allocated_alpha_g1(a);
    grpc_verification_key_groth16->set_allocated_beta_g2(b);
    grpc_verification_key_groth16->set_allocated_delta_g2(d);
    grpc_verification_key_groth16->set_abc_g1(abc_json_str);
}

} // namespace libzeth

#endif // __ZETH_SNARKS_GROTH16_GROTH16_API_TCC__
