#ifndef __ZETH_GROTH16_RESPONSE_TCC__
#define __ZETH_GROTH16_RESPONSE_TCC__

namespace libzeth{
    template<typename ppT>
    void PrepareProofResponse(extended_proof<ppT>& ext_proof, ExtendedProof* message) {
        libsnark::r1cs_ppzksnark_proof<ppT> proofObj = ext_proof.get_proof();

        HexadecimalPointBaseGroup1Affine *a = new HexadecimalPointBaseGroup1Affine();
        HexadecimalPointBaseGroup2Affine *b = new HexadecimalPointBaseGroup2Affine(); // in G2
        HexadecimalPointBaseGroup1Affine *c = new HexadecimalPointBaseGroup1Affine();

        a->CopyFrom(FormatHexadecimalPointBaseGroup1Affine(proofObj.a));
        b->CopyFrom(FormatHexadecimalPointBaseGroup2Affine(proofObj.b)); // in G2
        c->CopyFrom(FormatHexadecimalPointBaseGroup1Affine(proofObj.c));

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
        r1csPpzksnarkExtendedProof->set_inputs(inputs_json);
    }
    
    template<typename ppT>
    void PrepareVerifyingKeyResponse(libsnark::r1cs_gg_ppzksnark_verification_key<ppT>& vk, VerificationKey* message) {
        HexadecimalPointBaseGroup2Affine *agbg = new HexadecimalPointBaseGroupT(); // in GT
        HexadecimalPointBaseGroup2Affine *g = new HexadecimalPointBaseGroup2Affine(); // in G2
        HexadecimalPointBaseGroup2Affine *d = new HexadecimalPointBaseGroup2Affine(); // in G2

        abgb->CopyFrom(FormatHexadecimalPointBaseGroupT(vk.alpha_g1_beta_g2)); // in GT
        g->CopyFrom(FormatHexadecimalPointBaseGroup2Affine(vk.gamma_g2)); // in G2
        d->CopyFrom(FormatHexadecimalPointBaseGroup2Affine(vk.delta_g2)); // in G2

        std::stringstream ss;
        unsigned gammaABCLength = keypair.vk.gamma_ABC_g1.rest.indices.size() + 1;
        ss <<  "[[" << outputPointG1AffineAsHex(vk.gamma_ABC_g1.first) << "]";
        for (size_t i = 1; i < icLength; ++i) {
            auto vkGammaABCi = outputPointG1AffineAsHex(keypair.vk.gamma_ABC_g1.rest.values[i - 1]);
            ss << ",[" <<  vkGammaABCi << "]";
        }
        ss << "]";
        std::string GammaABC_json = ss.str();

        // Note on memory safety: set_allocated deleted the allocated objects
        // See: https://stackoverflow.com/questions/33960999/protobuf-will-set-allocated-delete-the-allocated-object
        R1csGgPpzksnarkVerificationKey *r1csGgPpzksnarkVerificationKey = message->mutable_r1csggppzksnarkverificationkey();

        r1csGgPpzksnarkVerificationKey->set_allocated_agbg(agbg);
        r1csGgPpzksnarkVerificationKey->set_allocated_g(g);
        r1csGgPpzksnarkVerificationKey->set_allocated_d(d);
        r1csGgPpzksnarkVerificationKey->set_ic(GammaABC_json);
    }
}

#endif