// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SNARKS_GROTH16_GROTH16_API_HANDLER_TCC__
#define __ZETH_SNARKS_GROTH16_GROTH16_API_HANDLER_TCC__

#include "libzeth/core/field_element_utils.hpp"
#include "libzeth/serialization/proto_utils.hpp"
#include "libzeth/serialization/r1cs_serialization.hpp"
#include "libzeth/snarks/groth16/groth16_api_handler.hpp"

namespace libzeth
{

template<typename ppT>
void groth16_api_handler<ppT>::verification_key_to_proto(
    const typename groth16_api_handler<ppT>::snark::verification_key &vk,
    zeth_proto::VerificationKey *message)
{
    zeth_proto::HexPointBaseGroup1Affine *a =
        new zeth_proto::HexPointBaseGroup1Affine();
    zeth_proto::HexPointBaseGroup2Affine *b =
        new zeth_proto::HexPointBaseGroup2Affine();
    zeth_proto::HexPointBaseGroup2Affine *d =
        new zeth_proto::HexPointBaseGroup2Affine();

    a->CopyFrom(point_g1_affine_to_proto<ppT>(vk.alpha_g1));
    b->CopyFrom(point_g2_affine_to_proto<ppT>(vk.beta_g2));
    d->CopyFrom(point_g2_affine_to_proto<ppT>(vk.delta_g2));

    std::string abc_json_str = accumulation_vector_to_json<ppT>(vk.ABC_g1);

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
typename groth16_snark<ppT>::verification_key groth16_api_handler<
    ppT>::verification_key_from_proto(const zeth_proto::VerificationKey
                                          &verification_key)
{
    const zeth_proto::VerificationKeyGROTH16 &verif_key =
        verification_key.groth16_verification_key();
    libff::G1<ppT> alpha_g1 =
        point_g1_affine_from_proto<ppT>(verif_key.alpha_g1());
    libff::G2<ppT> beta_g2 =
        point_g2_affine_from_proto<ppT>(verif_key.beta_g2());

    libff::G2<ppT> delta_g2 =
        point_g2_affine_from_proto<ppT>(verif_key.delta_g2());

    libsnark::accumulation_vector<libff::G1<ppT>> abc_g1 =
        accumulation_vector_from_json<ppT>(verif_key.abc_g1());

    libsnark::r1cs_gg_ppzksnark_verification_key<ppT> vk(
        alpha_g1, beta_g2, delta_g2, abc_g1);

    return vk;
}

template<typename ppT>
void groth16_api_handler<ppT>::extended_proof_to_proto(
    const extended_proof<ppT, groth16_api_handler<ppT>::snark> &ext_proof,
    zeth_proto::ExtendedProof *message)
{
    libsnark::r1cs_gg_ppzksnark_proof<ppT> proof_obj = ext_proof.get_proof();

    zeth_proto::HexPointBaseGroup1Affine *a =
        new zeth_proto::HexPointBaseGroup1Affine();
    zeth_proto::HexPointBaseGroup2Affine *b =
        new zeth_proto::HexPointBaseGroup2Affine();
    zeth_proto::HexPointBaseGroup1Affine *c =
        new zeth_proto::HexPointBaseGroup1Affine();

    a->CopyFrom(point_g1_affine_to_proto<ppT>(proof_obj.g_A));
    b->CopyFrom(point_g2_affine_to_proto<ppT>(proof_obj.g_B));
    c->CopyFrom(point_g1_affine_to_proto<ppT>(proof_obj.g_C));

    std::stringstream ss;
    primary_inputs_write_json(ss, ext_proof.get_primary_inputs());

    // Note on memory safety: set_allocated deleted the allocated objects.
    // See:
    // https://stackoverflow.com/questions/33960999/protobuf-will-set-allocated-delete-the-allocated-object
    zeth_proto::ExtendedProofGROTH16 *grpc_extended_groth16_proof_obj =
        message->mutable_groth16_extended_proof();

    grpc_extended_groth16_proof_obj->set_allocated_a(a);
    grpc_extended_groth16_proof_obj->set_allocated_b(b);
    grpc_extended_groth16_proof_obj->set_allocated_c(c);
    grpc_extended_groth16_proof_obj->set_inputs(ss.str());
}

template<typename ppT>
libzeth::extended_proof<ppT, groth16_snark<ppT>> groth16_api_handler<
    ppT>::extended_proof_from_proto(const zeth_proto::ExtendedProof &ext_proof)
{
    const zeth_proto::ExtendedProofGROTH16 &e_proof =
        ext_proof.groth16_extended_proof();
    libff::G1<ppT> a = point_g1_affine_from_proto<ppT>(e_proof.a());
    libff::G2<ppT> b = point_g2_affine_from_proto<ppT>(e_proof.b());
    libff::G1<ppT> c = point_g1_affine_from_proto<ppT>(e_proof.c());

    std::vector<libff::Fr<ppT>> inputs;
    std::stringstream ss(e_proof.inputs());
    primary_inputs_read_json(ss, inputs);

    libsnark::r1cs_gg_ppzksnark_proof<ppT> proof(
        std::move(a), std::move(b), std::move(c));
    libzeth::extended_proof<ppT, groth16_snark<ppT>> res(
        std::move(proof), std::move(inputs));

    return res;
}

} // namespace libzeth

#endif // __ZETH_SNARKS_GROTH16_GROTH16_API_HANDLER_TCC__
