// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SNARKS_PGHR13_PGHR13_API_HANDLER_TCC__
#define __ZETH_SNARKS_PGHR13_PGHR13_API_HANDLER_TCC__

#include "libzeth/core/field_element_utils.hpp"
#include "libzeth/core/group_element_utils.hpp"
#include "libzeth/serialization/proto_utils.hpp"
#include "libzeth/serialization/r1cs_serialization.hpp"
#include "libzeth/snarks/pghr13/pghr13_api_handler.hpp"

namespace libzeth
{

template<typename ppT>
void pghr13_api_handler<ppT>::verification_key_to_proto(
    const typename snark::verification_key &vk,
    zeth_proto::VerificationKey *message)
{
    zeth_proto::HexPointBaseGroup2Affine *a =
        new zeth_proto::HexPointBaseGroup2Affine();
    zeth_proto::HexPointBaseGroup1Affine *b =
        new zeth_proto::HexPointBaseGroup1Affine();
    zeth_proto::HexPointBaseGroup2Affine *c =
        new zeth_proto::HexPointBaseGroup2Affine();
    zeth_proto::HexPointBaseGroup2Affine *g =
        new zeth_proto::HexPointBaseGroup2Affine();
    zeth_proto::HexPointBaseGroup1Affine *gb1 =
        new zeth_proto::HexPointBaseGroup1Affine();
    zeth_proto::HexPointBaseGroup2Affine *gb2 =
        new zeth_proto::HexPointBaseGroup2Affine();
    zeth_proto::HexPointBaseGroup2Affine *z =
        new zeth_proto::HexPointBaseGroup2Affine();

    a->CopyFrom(point_g2_affine_to_proto<ppT>(vk.alphaA_g2));
    b->CopyFrom(point_g1_affine_to_proto<ppT>(vk.alphaB_g1));
    c->CopyFrom(point_g2_affine_to_proto<ppT>(vk.alphaC_g2));
    g->CopyFrom(point_g2_affine_to_proto<ppT>(vk.gamma_g2));
    gb1->CopyFrom(point_g1_affine_to_proto<ppT>(vk.gamma_beta_g1));
    gb2->CopyFrom(point_g2_affine_to_proto<ppT>(vk.gamma_beta_g2));
    z->CopyFrom(point_g2_affine_to_proto<ppT>(vk.rC_Z_g2));

    std::string ic_json = accumulation_vector_to_json<ppT>(vk.encoded_IC_query);

    // Note on memory safety: set_allocated deleted the allocated objects
    // See:
    //   https://stackoverflow.com/questions/33960999/protobuf-will-set-allocated-delete-the-allocated-object
    zeth_proto::VerificationKeyPGHR13 *grpc_verification_key_pghr13 =
        message->mutable_pghr13_verification_key();

    grpc_verification_key_pghr13->set_allocated_a(a);
    grpc_verification_key_pghr13->set_allocated_b(b);
    grpc_verification_key_pghr13->set_allocated_c(c);
    grpc_verification_key_pghr13->set_allocated_gamma(g);
    grpc_verification_key_pghr13->set_allocated_gamma_beta_g1(gb1);
    grpc_verification_key_pghr13->set_allocated_gamma_beta_g2(gb2);
    grpc_verification_key_pghr13->set_allocated_z(z);
    grpc_verification_key_pghr13->set_ic(ic_json);
}

template<typename ppT>
typename pghr13_snark<ppT>::verification_key pghr13_api_handler<
    ppT>::verification_key_from_proto(const zeth_proto::VerificationKey
                                          &verification_key)
{
    const zeth_proto::VerificationKeyPGHR13 &verif_key =
        verification_key.pghr13_verification_key();
    libff::G2<ppT> a = point_g2_affine_from_proto<ppT>(verif_key.a());
    libff::G1<ppT> b = point_g1_affine_from_proto<ppT>(verif_key.b());
    libff::G2<ppT> c = point_g2_affine_from_proto<ppT>(verif_key.c());
    libff::G2<ppT> gamma = point_g2_affine_from_proto<ppT>(verif_key.gamma());
    libff::G1<ppT> gamma_beta_g1 =
        point_g1_affine_from_proto<ppT>(verif_key.gamma_beta_g1());
    libff::G2<ppT> gamma_beta_g2 =
        point_g2_affine_from_proto<ppT>(verif_key.gamma_beta_g2());
    libff::G2<ppT> z = point_g2_affine_from_proto<ppT>(verif_key.z());

    libsnark::accumulation_vector<libff::G1<ppT>> ic =
        accumulation_vector_from_json<ppT>(verif_key.ic());

    libsnark::r1cs_ppzksnark_verification_key<ppT> vk(
        a, b, c, gamma, gamma_beta_g1, gamma_beta_g2, z, ic);

    return vk;
}

template<typename ppT>
void pghr13_api_handler<ppT>::extended_proof_to_proto(
    const extended_proof<ppT, snark> &ext_proof,
    zeth_proto::ExtendedProof *message)
{
    libsnark::r1cs_ppzksnark_proof<ppT> proofObj = ext_proof.get_proof();

    zeth_proto::HexPointBaseGroup1Affine *a =
        new zeth_proto::HexPointBaseGroup1Affine();
    zeth_proto::HexPointBaseGroup1Affine *a_p =
        new zeth_proto::HexPointBaseGroup1Affine();
    zeth_proto::HexPointBaseGroup2Affine *b =
        new zeth_proto::HexPointBaseGroup2Affine();
    zeth_proto::HexPointBaseGroup1Affine *b_p =
        new zeth_proto::HexPointBaseGroup1Affine();
    zeth_proto::HexPointBaseGroup1Affine *c =
        new zeth_proto::HexPointBaseGroup1Affine();
    zeth_proto::HexPointBaseGroup1Affine *c_p =
        new zeth_proto::HexPointBaseGroup1Affine();
    zeth_proto::HexPointBaseGroup1Affine *h =
        new zeth_proto::HexPointBaseGroup1Affine();
    zeth_proto::HexPointBaseGroup1Affine *k =
        new zeth_proto::HexPointBaseGroup1Affine();

    a->CopyFrom(point_g1_affine_to_proto<ppT>(proofObj.g_A.g));
    a_p->CopyFrom(point_g1_affine_to_proto<ppT>(proofObj.g_A.h));
    b->CopyFrom(point_g2_affine_to_proto<ppT>(proofObj.g_B.g));
    b_p->CopyFrom(point_g1_affine_to_proto<ppT>(proofObj.g_B.h));
    c->CopyFrom(point_g1_affine_to_proto<ppT>(proofObj.g_C.g));
    c_p->CopyFrom(point_g1_affine_to_proto<ppT>(proofObj.g_C.h));
    h->CopyFrom(point_g1_affine_to_proto<ppT>(proofObj.g_H));
    k->CopyFrom(point_g1_affine_to_proto<ppT>(proofObj.g_K));

    libsnark::r1cs_ppzksnark_primary_input<ppT> pub_inputs =
        ext_proof.get_primary_inputs();

    std::stringstream ss;
    primary_inputs_write_json(pub_inputs, ss);

    // Note on memory safety: set_allocated deleted the allocated objects
    // See:
    //   https://stackoverflow.com/questions/33960999/protobuf-will-set-allocated-delete-the-allocated-object
    zeth_proto::ExtendedProofPGHR13 *grpc_extended_pghr13_proof_obj =
        message->mutable_pghr13_extended_proof();

    grpc_extended_pghr13_proof_obj->set_allocated_a(a);
    grpc_extended_pghr13_proof_obj->set_allocated_a_p(a_p);
    grpc_extended_pghr13_proof_obj->set_allocated_b(b);
    grpc_extended_pghr13_proof_obj->set_allocated_b_p(b_p);
    grpc_extended_pghr13_proof_obj->set_allocated_c(c);
    grpc_extended_pghr13_proof_obj->set_allocated_c_p(c_p);
    grpc_extended_pghr13_proof_obj->set_allocated_h(h);
    grpc_extended_pghr13_proof_obj->set_allocated_k(k);
    grpc_extended_pghr13_proof_obj->set_inputs(ss.str());
}

template<typename ppT>
libzeth::extended_proof<ppT, pghr13_snark<ppT>> pghr13_api_handler<
    ppT>::extended_proof_from_proto(const zeth_proto::ExtendedProof &ext_proof)
{
    const zeth_proto::ExtendedProofPGHR13 &e_proof =
        ext_proof.pghr13_extended_proof();

    libff::G1<ppT> a = point_g1_affine_from_proto<ppT>(e_proof.a());
    libff::G1<ppT> a_p = point_g1_affine_from_proto<ppT>(e_proof.a_p());
    libsnark::knowledge_commitment<libff::G1<ppT>, libff::G1<ppT>> g_A(a, a_p);

    libff::G2<ppT> b = point_g2_affine_from_proto<ppT>(e_proof.b());
    libff::G1<ppT> b_p = point_g1_affine_from_proto<ppT>(e_proof.b_p());
    libsnark::knowledge_commitment<libff::G2<ppT>, libff::G1<ppT>> g_B(b, b_p);

    libff::G1<ppT> c = point_g1_affine_from_proto<ppT>(e_proof.c());
    libff::G1<ppT> c_p = point_g1_affine_from_proto<ppT>(e_proof.c_p());
    libsnark::knowledge_commitment<libff::G1<ppT>, libff::G1<ppT>> g_C(c, c_p);

    libff::G1<ppT> h = point_g1_affine_from_proto<ppT>(e_proof.h());
    libff::G1<ppT> k = point_g1_affine_from_proto<ppT>(e_proof.k());

    libsnark::r1cs_ppzksnark_proof<ppT> proof(
        std::move(g_A),
        std::move(g_B),
        std::move(g_C),
        std::move(h),
        std::move(k));
    libsnark::r1cs_primary_input<libff::Fr<ppT>> inputs;
    std::stringstream ss(e_proof.inputs());
    primary_inputs_read_json(inputs, ss);

    return libzeth::extended_proof<ppT, pghr13_snark<ppT>>(
        std::move(proof), std::move(inputs));
}

} // namespace libzeth

#endif // __ZETH_SNARKS_PGHR13_PGHR13_API_HANDLER_TCC__
