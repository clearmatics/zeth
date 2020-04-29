// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_SNARKS_PGHR13_PGHR13_API_HANDLER_TCC__
#define __ZETH_SNARKS_PGHR13_PGHR13_API_HANDLER_TCC__

#include "libzeth/sciprlab_libs_util.hpp"
#include "libzeth/serialization/api/api_io.hpp"
#include "libzeth/snarks/pghr13/pghr13_api_handler.hpp"

namespace libzeth
{

template<typename ppT>
void pghr13_api_handler<ppT>::format_extended_proof(
    const extended_proof<ppT, snarkT> &ext_proof,
    zeth_proto::ExtendedProof *message)
{
    libsnark::r1cs_ppzksnark_proof<ppT> proofObj = ext_proof.get_proof();

    zeth_proto::HexPointBaseGroup1Affine *a =
        new zeth_proto::HexPointBaseGroup1Affine();
    zeth_proto::HexPointBaseGroup1Affine *a_p =
        new zeth_proto::HexPointBaseGroup1Affine();
    zeth_proto::HexPointBaseGroup2Affine *b =
        new zeth_proto::HexPointBaseGroup2Affine(); // in G2
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

    a->CopyFrom(format_hexPointBaseGroup1Affine<ppT>(proofObj.g_A.g));
    a_p->CopyFrom(format_hexPointBaseGroup1Affine<ppT>(proofObj.g_A.h));
    b->CopyFrom(format_hexPointBaseGroup2Affine<ppT>(proofObj.g_B.g)); // in G2
    b_p->CopyFrom(format_hexPointBaseGroup1Affine<ppT>(proofObj.g_B.h));
    c->CopyFrom(format_hexPointBaseGroup1Affine<ppT>(proofObj.g_C.g));
    c_p->CopyFrom(format_hexPointBaseGroup1Affine<ppT>(proofObj.g_C.h));
    h->CopyFrom(format_hexPointBaseGroup1Affine<ppT>(proofObj.g_H));
    k->CopyFrom(format_hexPointBaseGroup1Affine<ppT>(proofObj.g_K));

    libsnark::r1cs_ppzksnark_primary_input<ppT> pub_inputs =
        ext_proof.get_primary_inputs();

    std::string inputs_json =
        format_primary_inputs<ppT>(std::vector<libff::Fr<ppT>>(pub_inputs));

    // Note on memory safety: set_allocated deleted the allocated objects
    // See:
    // https://stackoverflow.com/questions/33960999/protobuf-will-set-allocated-delete-the-allocated-object
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
    grpc_extended_pghr13_proof_obj->set_inputs(inputs_json);
}

template<typename ppT>
void pghr13_api_handler<ppT>::format_verification_key(
    const typename snarkT::VerifKeyT &vk, zeth_proto::VerificationKey *message)
{
    zeth_proto::HexPointBaseGroup2Affine *a =
        new zeth_proto::HexPointBaseGroup2Affine(); // in G2
    zeth_proto::HexPointBaseGroup1Affine *b =
        new zeth_proto::HexPointBaseGroup1Affine(); // in G1
    zeth_proto::HexPointBaseGroup2Affine *c =
        new zeth_proto::HexPointBaseGroup2Affine(); // in G2
    zeth_proto::HexPointBaseGroup2Affine *g =
        new zeth_proto::HexPointBaseGroup2Affine(); // in G2
    zeth_proto::HexPointBaseGroup1Affine *gb1 =
        new zeth_proto::HexPointBaseGroup1Affine(); // in G1
    zeth_proto::HexPointBaseGroup2Affine *gb2 =
        new zeth_proto::HexPointBaseGroup2Affine(); // in G2
    zeth_proto::HexPointBaseGroup2Affine *z =
        new zeth_proto::HexPointBaseGroup2Affine(); // in G2

    a->CopyFrom(format_hexPointBaseGroup2Affine<ppT>(vk.alphaA_g2)); // in G2
    b->CopyFrom(format_hexPointBaseGroup1Affine<ppT>(vk.alphaB_g1)); // in G1
    c->CopyFrom(format_hexPointBaseGroup2Affine<ppT>(vk.alphaC_g2)); // in G2
    g->CopyFrom(format_hexPointBaseGroup2Affine<ppT>(vk.gamma_g2));  // in G2
    gb1->CopyFrom(
        format_hexPointBaseGroup1Affine<ppT>(vk.gamma_beta_g1)); // in G1
    gb2->CopyFrom(
        format_hexPointBaseGroup2Affine<ppT>(vk.gamma_beta_g2));   // in G2
    z->CopyFrom(format_hexPointBaseGroup2Affine<ppT>(vk.rC_Z_g2)); // in G2

    std::stringstream ss;
    unsigned ic_length = vk.encoded_IC_query.rest.indices.size() + 1;
    ss << "[[" << point_g1_affine_to_hex<ppT>(vk.encoded_IC_query.first) << "]";
    for (size_t i = 1; i < ic_length; ++i) {
        auto vk_ic_i =
            point_g1_affine_to_hex<ppT>(vk.encoded_IC_query.rest.values[i - 1]);
        ss << ",[" << vk_ic_i << "]";
    }
    ss << "]";
    std::string ic_json = ss.str();

    // Note on memory safety: set_allocated deleted the allocated objects
    // See:
    // https://stackoverflow.com/questions/33960999/protobuf-will-set-allocated-delete-the-allocated-object
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
libzeth::extended_proof<ppT, pghr13_snark<ppT>> pghr13_api_handler<
    ppT>::parse_extended_proof(const zeth_proto::ExtendedProof &ext_proof)
{
    const zeth_proto::ExtendedProofPGHR13 &e_proof =
        ext_proof.pghr13_extended_proof();

    libff::G1<ppT> a = parse_hexPointBaseGroup1Affine<ppT>(e_proof.a());
    libff::G1<ppT> a_p = parse_hexPointBaseGroup1Affine<ppT>(e_proof.a_p());
    libsnark::knowledge_commitment<libff::G1<ppT>, libff::G1<ppT>> g_A(a, a_p);

    libff::G2<ppT> b = parse_hexPointBaseGroup2Affine<ppT>(e_proof.b());
    libff::G1<ppT> b_p = parse_hexPointBaseGroup1Affine<ppT>(e_proof.b_p());
    libsnark::knowledge_commitment<libff::G2<ppT>, libff::G1<ppT>> g_B(b, b_p);

    libff::G1<ppT> c = parse_hexPointBaseGroup1Affine<ppT>(e_proof.c());
    libff::G1<ppT> c_p = parse_hexPointBaseGroup1Affine<ppT>(e_proof.c_p());
    libsnark::knowledge_commitment<libff::G1<ppT>, libff::G1<ppT>> g_C(c, c_p);

    libff::G1<ppT> h = parse_hexPointBaseGroup1Affine<ppT>(e_proof.h());
    libff::G1<ppT> k = parse_hexPointBaseGroup1Affine<ppT>(e_proof.k());

    libsnark::r1cs_ppzksnark_proof<ppT> proof(
        std::move(g_A),
        std::move(g_B),
        std::move(g_C),
        std::move(h),
        std::move(k));
    libsnark::r1cs_primary_input<libff::Fr<ppT>> inputs =
        libsnark::r1cs_primary_input<libff::Fr<ppT>>(
            parse_str_primary_inputs<ppT>(e_proof.inputs()));
    libzeth::extended_proof<ppT, snarkT> res(proof, inputs);
    return res;
}

template<typename ppT>
typename pghr13_snark<ppT>::VerifKeyT pghr13_api_handler<ppT>::
    parse_verification_key(const zeth_proto::VerificationKey &verification_key)
{
    const zeth_proto::VerificationKeyPGHR13 &verif_key =
        verification_key.pghr13_verification_key();
    // G2
    libff::G2<ppT> a = parse_hexPointBaseGroup2Affine<ppT>(verif_key.a());
    // G1
    libff::G1<ppT> b = parse_hexPointBaseGroup1Affine<ppT>(verif_key.b());
    // G2
    libff::G2<ppT> c = parse_hexPointBaseGroup2Affine<ppT>(verif_key.c());
    // G2
    libff::G1<ppT> gamma =
        parse_hexPointBaseGroup2Affine<ppT>(verif_key.gamma());
    // G1
    libff::G1<ppT> gamma_beta_g1 =
        parse_hexPointBaseGroup1Affine<ppT>(verif_key.gamma_beta_g1());
    // G2
    libff::G2<ppT> gamma_beta_g2 =
        parse_hexPointBaseGroup2Affine<ppT>(verif_key.gamma_beta_g2());
    // G2
    libff::G2<ppT> z = parse_hexPointBaseGroup2Affine<ppT>(verif_key.z());

    libsnark::accumulation_vector<libff::G1<ppT>> ic =
        parse_str_accumulation_vector<ppT>(verif_key.ic());

    libsnark::r1cs_ppzksnark_verification_key<ppT> vk(
        a, b, c, gamma, gamma_beta_g1, gamma_beta_g2, z, ic);

    return vk;
}

template<typename ppT>
void pghr13_api_handler<ppT>::prepare_proof_response(
    const extended_proof<ppT, snarkT> &ext_proof,
    zeth_proto::ExtendedProof *message)
{
    libsnark::r1cs_ppzksnark_proof<ppT> proofObj = ext_proof.get_proof();

    zeth_proto::HexPointBaseGroup1Affine *a =
        new zeth_proto::HexPointBaseGroup1Affine();
    zeth_proto::HexPointBaseGroup1Affine *a_p =
        new zeth_proto::HexPointBaseGroup1Affine();
    zeth_proto::HexPointBaseGroup2Affine *b =
        new zeth_proto::HexPointBaseGroup2Affine(); // in G2
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

    a->CopyFrom(format_hexPointBaseGroup1Affine<ppT>(proofObj.g_A.g));
    a_p->CopyFrom(format_hexPointBaseGroup1Affine<ppT>(proofObj.g_A.h));
    b->CopyFrom(format_hexPointBaseGroup2Affine<ppT>(proofObj.g_B.g)); // in G2
    b_p->CopyFrom(format_hexPointBaseGroup1Affine<ppT>(proofObj.g_B.h));
    c->CopyFrom(format_hexPointBaseGroup1Affine<ppT>(proofObj.g_C.g));
    c_p->CopyFrom(format_hexPointBaseGroup1Affine<ppT>(proofObj.g_C.h));
    h->CopyFrom(format_hexPointBaseGroup1Affine<ppT>(proofObj.g_H));
    k->CopyFrom(format_hexPointBaseGroup1Affine<ppT>(proofObj.g_K));

    libsnark::r1cs_ppzksnark_primary_input<ppT> pub_inputs =
        ext_proof.get_primary_input();

    std::string inputs_json =
        format_primary_inputs<ppT>(std::vector<libff::Fr<ppT>>(pub_inputs));

    // Note on memory safety: set_allocated deleted the allocated objects
    // See:
    // https://stackoverflow.com/questions/33960999/protobuf-will-set-allocated-delete-the-allocated-object
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
    grpc_extended_pghr13_proof_obj->set_inputs(inputs_json);
}

template<typename ppT>
void pghr13_api_handler<ppT>::prepare_verification_key_response(
    const typename snarkT::VerifKeyT &vk, zeth_proto::VerificationKey *message)
{
    zeth_proto::HexPointBaseGroup2Affine *a =
        new zeth_proto::HexPointBaseGroup2Affine(); // in G2
    zeth_proto::HexPointBaseGroup1Affine *b =
        new zeth_proto::HexPointBaseGroup1Affine(); // in G1
    zeth_proto::HexPointBaseGroup2Affine *c =
        new zeth_proto::HexPointBaseGroup2Affine(); // in G2
    zeth_proto::HexPointBaseGroup2Affine *g =
        new zeth_proto::HexPointBaseGroup2Affine(); // in G2
    zeth_proto::HexPointBaseGroup1Affine *gb1 =
        new zeth_proto::HexPointBaseGroup1Affine(); // in G1
    zeth_proto::HexPointBaseGroup2Affine *gb2 =
        new zeth_proto::HexPointBaseGroup2Affine(); // in G2
    zeth_proto::HexPointBaseGroup2Affine *z =
        new zeth_proto::HexPointBaseGroup2Affine(); // in G2

    a->CopyFrom(format_hexPointBaseGroup2Affine<ppT>(vk.alphaA_g2)); // in G2
    b->CopyFrom(format_hexPointBaseGroup1Affine<ppT>(vk.alphaB_g1)); // in G1
    c->CopyFrom(format_hexPointBaseGroup2Affine<ppT>(vk.alphaC_g2)); // in G2
    g->CopyFrom(format_hexPointBaseGroup2Affine<ppT>(vk.gamma_g2));  // in G2
    gb1->CopyFrom(
        format_hexPointBaseGroup1Affine<ppT>(vk.gamma_beta_g1)); // in G1
    gb2->CopyFrom(
        format_hexPointBaseGroup2Affine<ppT>(vk.gamma_beta_g2));   // in G2
    z->CopyFrom(format_hexPointBaseGroup2Affine<ppT>(vk.rC_Z_g2)); // in G2

    std::stringstream ss;
    unsigned ic_length = vk.encoded_IC_query.rest.indices.size() + 1;
    ss << "[[" << point_g1_affine_to_hex<ppT>(vk.encoded_IC_query.first) << "]";
    for (size_t i = 1; i < ic_length; ++i) {
        auto vk_ic_i =
            point_g1_affine_to_hex<ppT>(vk.encoded_IC_query.rest.values[i - 1]);
        ss << ",[" << vk_ic_i << "]";
    }
    ss << "]";
    std::string ic_json = ss.str();

    // Note on memory safety: set_allocated deleted the allocated objects
    // See:
    // https://stackoverflow.com/questions/33960999/protobuf-will-set-allocated-delete-the-allocated-object
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

} // namespace libzeth

#endif // __ZETH_SNARKS_PGHR13_PGHR13_API_HANDLER_TCC__
