#ifndef __ZETH_RESPONSE_TCC__
#define __ZETH_RESPONSE_TCC__

namespace libzeth
{

template<typename ppT>
void prepare_proof_response(
    extended_proof<ppT> &ext_proof, prover_proto::ExtendedProof *message)
{
    libsnark::r1cs_ppzksnark_proof<ppT> proofObj = ext_proof.get_proof();

    prover_proto::HexadecimalPointBaseGroup1Affine *a =
        new prover_proto::HexadecimalPointBaseGroup1Affine();
    prover_proto::HexadecimalPointBaseGroup1Affine *a_p =
        new prover_proto::HexadecimalPointBaseGroup1Affine();
    prover_proto::HexadecimalPointBaseGroup2Affine *b =
        new prover_proto::HexadecimalPointBaseGroup2Affine(); // in G2
    prover_proto::HexadecimalPointBaseGroup1Affine *b_p =
        new prover_proto::HexadecimalPointBaseGroup1Affine();
    prover_proto::HexadecimalPointBaseGroup1Affine *c =
        new prover_proto::HexadecimalPointBaseGroup1Affine();
    prover_proto::HexadecimalPointBaseGroup1Affine *c_p =
        new prover_proto::HexadecimalPointBaseGroup1Affine();
    prover_proto::HexadecimalPointBaseGroup1Affine *h =
        new prover_proto::HexadecimalPointBaseGroup1Affine();
    prover_proto::HexadecimalPointBaseGroup1Affine *k =
        new prover_proto::HexadecimalPointBaseGroup1Affine();

    a->CopyFrom(format_hexadecimalPointBaseGroup1Affine(proofObj.g_A.g));
    a_p->CopyFrom(format_hexadecimalPointBaseGroup1Affine(proofObj.g_A.h));
    b->CopyFrom(
        format_hexadecimalPointBaseGroup2Affine(proofObj.g_B.g)); // in G2
    b_p->CopyFrom(format_hexadecimalPointBaseGroup1Affine(proofObj.g_B.h));
    c->CopyFrom(format_hexadecimalPointBaseGroup1Affine(proofObj.g_C.g));
    c_p->CopyFrom(format_hexadecimalPointBaseGroup1Affine(proofObj.g_C.h));
    h->CopyFrom(format_hexadecimalPointBaseGroup1Affine(proofObj.g_H));
    k->CopyFrom(format_hexadecimalPointBaseGroup1Affine(proofObj.g_K));

    libsnark::r1cs_ppzksnark_primary_input<ppT> pub_inputs =
        ext_proof.get_primary_input();
    std::stringstream ss;
    ss << "[";
    for (size_t i = 0; i < pub_inputs.size(); ++i) {
        ss << "\"0x"
           << hex_string_from_libsnark_bigint(pub_inputs[i].as_bigint())
           << "\"";
        if (i < pub_inputs.size() - 1) {
            ss << ", ";
        }
    }
    ss << "]";
    std::string inputs_json = ss.str();

    // Note on memory safety: set_allocated deleted the allocated objects
    // See:
    // https://stackoverflow.com/questions/33960999/protobuf-will-set-allocated-delete-the-allocated-object
    prover_proto::ExtendedProofPGHR13 *grpc_extended_pghr13_proof_obj =
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
void prepare_verification_key_response(
    libsnark::r1cs_ppzksnark_verification_key<ppT> &vk,
    prover_proto::VerificationKey *message)
{
    prover_proto::HexadecimalPointBaseGroup2Affine *a =
        new prover_proto::HexadecimalPointBaseGroup2Affine(); // in G2
    prover_proto::HexadecimalPointBaseGroup1Affine *b =
        new prover_proto::HexadecimalPointBaseGroup1Affine(); // in G1
    prover_proto::HexadecimalPointBaseGroup2Affine *c =
        new prover_proto::HexadecimalPointBaseGroup2Affine(); // in G2
    prover_proto::HexadecimalPointBaseGroup2Affine *g =
        new prover_proto::HexadecimalPointBaseGroup2Affine(); // in G2
    prover_proto::HexadecimalPointBaseGroup1Affine *gb1 =
        new prover_proto::HexadecimalPointBaseGroup1Affine(); // in G1
    prover_proto::HexadecimalPointBaseGroup2Affine *gb2 =
        new prover_proto::HexadecimalPointBaseGroup2Affine(); // in G2
    prover_proto::HexadecimalPointBaseGroup2Affine *z =
        new prover_proto::HexadecimalPointBaseGroup2Affine(); // in G2

    a->CopyFrom(format_hexadecimalPointBaseGroup2Affine(vk.alphaA_g2)); // in G2
    b->CopyFrom(format_hexadecimalPointBaseGroup1Affine(vk.alphaB_g1)); // in G1
    c->CopyFrom(format_hexadecimalPointBaseGroup2Affine(vk.alphaC_g2)); // in G2
    g->CopyFrom(format_hexadecimalPointBaseGroup2Affine(vk.gamma_g2));  // in G2
    gb1->CopyFrom(
        format_hexadecimalPointBaseGroup1Affine(vk.gamma_beta_g1)); // in G1
    gb2->CopyFrom(
        format_hexadecimalPointBaseGroup2Affine(vk.gamma_beta_g2));   // in G2
    z->CopyFrom(format_hexadecimalPointBaseGroup2Affine(vk.rC_Z_g2)); // in G2

    std::stringstream ss;
    unsigned ic_length = vk.encoded_IC_query.rest.indices.size() + 1;
    ss << "[[" << get_point_g1_affine_as_hex_str(vk.encoded_IC_query.first)
       << "]";
    for (size_t i = 1; i < ic_length; ++i) {
        auto vk_ic_i = get_point_g1_affine_as_hex_str(
            vk.encoded_IC_query.rest.values[i - 1]);
        ss << ",[" << vk_ic_i << "]";
    }
    ss << "]";
    std::string ic_json = ss.str();

    // Note on memory safety: set_allocated deleted the allocated objects
    // See:
    // https://stackoverflow.com/questions/33960999/protobuf-will-set-allocated-delete-the-allocated-object
    prover_proto::VerificationKeyPGHR13 *grpc_verification_key_pghr13 =
        message->mutable_pghr13_verification_key();

    grpc_verification_key_pghr13->set_allocated_a(a);
    grpc_verification_key_pghr13->set_allocated_b(b);
    grpc_verification_key_pghr13->set_allocated_c(c);
    grpc_verification_key_pghr13->set_allocated_gamma(g);
    grpc_verification_key_pghr13->set_allocated_gamma_beta_g1(gb1);
    grpc_verification_key_pghr13->set_allocated_gamma_beta_g2(gb2);
    grpc_verification_key_pghr13->set_allocated_z(z);
    grpc_verification_key_pghr13->set_ic(ic_json);
};

} // namespace libzeth

#endif // __ZETH_RESPONSE_TCC__
