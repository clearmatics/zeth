#ifndef __ZETH_PGHR13_RESPONSE_TCC__
#define __ZETH_PGHR13_RESPONSE_TCC__

namespace libzeth{
template<typename ppT>
void PrepareProofResponse(extended_proof<ppT>& ext_proof, ExtendedProof* message) {
    libsnark::r1cs_ppzksnark_proof<ppT> proofObj = ext_proof.get_proof();

    HexadecimalPointBaseGroup1Affine *a = new HexadecimalPointBaseGroup1Affine();
    HexadecimalPointBaseGroup1Affine *a_p = new HexadecimalPointBaseGroup1Affine();
    HexadecimalPointBaseGroup2Affine *b = new HexadecimalPointBaseGroup2Affine(); // in G2
    HexadecimalPointBaseGroup1Affine *b_p = new HexadecimalPointBaseGroup1Affine();
    HexadecimalPointBaseGroup1Affine *c = new HexadecimalPointBaseGroup1Affine();
    HexadecimalPointBaseGroup1Affine *c_p = new HexadecimalPointBaseGroup1Affine();
    HexadecimalPointBaseGroup1Affine *h = new HexadecimalPointBaseGroup1Affine();
    HexadecimalPointBaseGroup1Affine *k = new HexadecimalPointBaseGroup1Affine();

    a->CopyFrom(FormatHexadecimalPointBaseGroup1Affine(proofObj.g_A.g));
    a_p->CopyFrom(FormatHexadecimalPointBaseGroup1Affine(proofObj.g_A.h));
    b->CopyFrom(FormatHexadecimalPointBaseGroup2Affine(proofObj.g_B.g)); // in G2
    b_p->CopyFrom(FormatHexadecimalPointBaseGroup1Affine(proofObj.g_B.h));
    c->CopyFrom(FormatHexadecimalPointBaseGroup1Affine(proofObj.g_C.g));
    c_p->CopyFrom(FormatHexadecimalPointBaseGroup1Affine(proofObj.g_C.h));
    h->CopyFrom(FormatHexadecimalPointBaseGroup1Affine(proofObj.g_H));
    k->CopyFrom(FormatHexadecimalPointBaseGroup1Affine(proofObj.g_K));

    libsnark::r1cs_ppzksnark_primary_input<ppT> pubInputs = ext_proof.get_primary_input();
    std::stringstream ss;
    ss << "[";
    for (size_t i = 0; i < pubInputs.size(); ++i) {
        ss << "\"0x" << HexStringFromLibsnarkBigint(pubInputs[i].as_bigint()) << "\"";
        if ( i < pubInputs.size() - 1 ) {
            ss<< ", ";
        }
    }
    ss << "]";
    std::string inputs_json = ss.str();

    // Note on memory safety: set_allocated deleted the allocated objects
    // See: https://stackoverflow.com/questions/33960999/protobuf-will-set-allocated-delete-the-allocated-object
    R1csPpzksnarkExtendedProof *r1csPpzksnarkExtendedProof = message->mutable_r1csppzksnarkextendedproof();
    
    r1csPpzksnarkExtendedProof->set_allocated_a(a);
    r1csPpzksnarkExtendedProof->set_allocated_ap(a_p);
    r1csPpzksnarkExtendedProof->set_allocated_b(b);
    r1csPpzksnarkExtendedProof->set_allocated_bp(b_p);
    r1csPpzksnarkExtendedProof->set_allocated_c(c);
    r1csPpzksnarkExtendedProof->set_allocated_cp(c_p);
    r1csPpzksnarkExtendedProof->set_allocated_h(h);
    r1csPpzksnarkExtendedProof->set_allocated_k(k);
    r1csPpzksnarkExtendedProof->set_inputs(inputs_json);
}

template<typename ppT>
void PrepareVerifyingKeyResponse(libsnark::r1cs_ppzksnark_verification_key<ppT>& vk, VerificationKey* message) {
    HexadecimalPointBaseGroup2Affine *a = new HexadecimalPointBaseGroup2Affine(); // in G2
    HexadecimalPointBaseGroup1Affine *b = new HexadecimalPointBaseGroup1Affine(); // in G1
    HexadecimalPointBaseGroup2Affine *c = new HexadecimalPointBaseGroup2Affine(); // in G2
    HexadecimalPointBaseGroup2Affine *g = new HexadecimalPointBaseGroup2Affine(); // in G2
    HexadecimalPointBaseGroup1Affine *gb1 = new HexadecimalPointBaseGroup1Affine(); // in G1
    HexadecimalPointBaseGroup2Affine *gb2 = new HexadecimalPointBaseGroup2Affine(); // in G2
    HexadecimalPointBaseGroup2Affine *z = new HexadecimalPointBaseGroup2Affine(); // in G2

    a->CopyFrom(FormatHexadecimalPointBaseGroup2Affine(vk.alphaA_g2)); // in G2
    b->CopyFrom(FormatHexadecimalPointBaseGroup1Affine(vk.alphaB_g1)); // in G1
    c->CopyFrom(FormatHexadecimalPointBaseGroup2Affine(vk.alphaC_g2)); // in G2
    g->CopyFrom(FormatHexadecimalPointBaseGroup2Affine(vk.gamma_g2)); // in G2
    gb1->CopyFrom(FormatHexadecimalPointBaseGroup1Affine(vk.gamma_beta_g1)); // in G1
    gb2->CopyFrom(FormatHexadecimalPointBaseGroup2Affine(vk.gamma_beta_g2)); // in G2
    z->CopyFrom(FormatHexadecimalPointBaseGroup2Affine(vk.rC_Z_g2)); // in G2

    std::stringstream ss;
    unsigned icLength = vk.encoded_IC_query.rest.indices.size() + 1;
    ss <<  "[[" << outputPointG1AffineAsHex(vk.encoded_IC_query.first) << "]";
    for (size_t i = 1; i < icLength; ++i) {
        auto vkICi = outputPointG1AffineAsHex(vk.encoded_IC_query.rest.values[i - 1]);
        ss << ",[" <<  vkICi << "]";
    }
    ss << "]";
    std::string IC_json = ss.str();

    // Note on memory safety: set_allocated deleted the allocated objects
    // See: https://stackoverflow.com/questions/33960999/protobuf-will-set-allocated-delete-the-allocated-object
    R1csPpzksnarkVerificationKey *r1csPpzksnarkVerificationKey = message->mutable_r1csppzksnarkverificationkey();

    r1csPpzksnarkVerificationKey->set_allocated_a(a);
    r1csPpzksnarkVerificationKey->set_allocated_b(b);
    r1csPpzksnarkVerificationKey->set_allocated_c(c);
    r1csPpzksnarkVerificationKey->set_allocated_g(g);
    r1csPpzksnarkVerificationKey->set_allocated_gb1(gb1);
    r1csPpzksnarkVerificationKey->set_allocated_gb2(gb2);
    r1csPpzksnarkVerificationKey->set_allocated_z(z);
    r1csPpzksnarkVerificationKey->set_ic(IC_json);
}
} //libzeth

#endif