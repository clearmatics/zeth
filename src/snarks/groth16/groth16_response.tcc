#ifndef __ZETH_GROTH16_RESPONSE_TCC__
#define __ZETH_GROTH16_RESPONSE_TCC__

namespace libzeth{
    template<typename ppT>
    void PrepareProofResponse(extended_proof<ppT>& ext_proof, ExtendedProof* message) {
        libsnark::r1cs_gg_ppzksnark_proof<ppT> proofObj = ext_proof.get_proof();

        HexadecimalPointBaseGroup1Affine *a = new HexadecimalPointBaseGroup1Affine();
        HexadecimalPointBaseGroup2Affine *b = new HexadecimalPointBaseGroup2Affine(); // in G2
        HexadecimalPointBaseGroup1Affine *c = new HexadecimalPointBaseGroup1Affine();

        a->CopyFrom(FormatHexadecimalPointBaseGroup1Affine(proofObj.g_A));
        b->CopyFrom(FormatHexadecimalPointBaseGroup2Affine(proofObj.g_B)); // in G2
        c->CopyFrom(FormatHexadecimalPointBaseGroup1Affine(proofObj.g_C));

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
        R1csGgPpzksnarkExtendedProof *r1csGgPpzksnarkExtendedProof = message->mutable_r1csggppzksnarkextendedproof();
        
        r1csGgPpzksnarkExtendedProof->set_allocated_a(a);
        r1csGgPpzksnarkExtendedProof->set_allocated_b(b);
        r1csGgPpzksnarkExtendedProof->set_allocated_c(c);
        r1csGgPpzksnarkExtendedProof->set_inputs(inputs_json);
    }
    
    template<typename ppT>
    void PrepareVerifyingKeyResponse(libsnark::r1cs_gg_ppzksnark_verification_key<ppT>& vk, VerificationKey* message) {
        HexadecimalPointBaseGroup1Affine *a = new HexadecimalPointBaseGroup1Affine(); // in G1
        HexadecimalPointBaseGroup2Affine *b = new HexadecimalPointBaseGroup2Affine(); // in G2
        HexadecimalPointBaseGroup2Affine *g = new HexadecimalPointBaseGroup2Affine(); // in G2
        HexadecimalPointBaseGroup2Affine *d = new HexadecimalPointBaseGroup2Affine(); // in G2

        a->CopyFrom(FormatHexadecimalPointBaseGroup1Affine(vk.alpha_g1)); // in G1
        b->CopyFrom(FormatHexadecimalPointBaseGroup2Affine(vk.beta_g2)); // in G2
        g->CopyFrom(FormatHexadecimalPointBaseGroup2Affine(vk.gamma_g2)); // in G2
        d->CopyFrom(FormatHexadecimalPointBaseGroup2Affine(vk.delta_g2)); // in G2

        std::stringstream ss;
        unsigned gammaABCLength = vk.gamma_ABC_g1.rest.indices.size() + 1;
        ss <<  "[[" << outputPointG1AffineAsHex(vk.gamma_ABC_g1.first) << "]";
        for (size_t i = 1; i < gammaABCLength; ++i) {
            auto vkGammaABCi = outputPointG1AffineAsHex(vk.gamma_ABC_g1.rest.values[i - 1]);
            ss << ",[" <<  vkGammaABCi << "]";
        }
        ss << "]";
        std::string GammaABC_json = ss.str();

        // Note on memory safety: set_allocated deleted the allocated objects
        // See: https://stackoverflow.com/questions/33960999/protobuf-will-set-allocated-delete-the-allocated-object
        R1csGgPpzksnarkVerificationKey *r1csGgPpzksnarkVerificationKey = message->mutable_r1csggppzksnarkverificationkey();

        r1csGgPpzksnarkVerificationKey->set_allocated_alpha_g1(a);
        r1csGgPpzksnarkVerificationKey->set_allocated_beta_g2(b);        
        r1csGgPpzksnarkVerificationKey->set_allocated_gamma_g2(g);
        r1csGgPpzksnarkVerificationKey->set_allocated_delta_g2(d);
        r1csGgPpzksnarkVerificationKey->set_gamma_abc_g1(GammaABC_json);
    }
}

#endif
