#ifndef __ZETH_NOTES_CIRCUITS_TCC__
#define __ZETH_NOTES_CIRCUITS_TCC__

// DISCLAIMER:
// Content Taken and adapted from Zcash
// https://github.com/zcash/zcash/blob/master/src/zcash/circuit/note.tcc

namespace libzeth {

template<typename FieldT>
note_gadget<FieldT>::note_gadget(libsnark::protoboard<FieldT> &pb,
                                const std::string &annotation_prefix
) : libsnark::gadget<FieldT>(pb, annotation_prefix)
{
    value.allocate(pb, ZETH_V_SIZE * 8); // ZETH_V_SIZE * 8 = 8 * 8 = 64
    r.allocate(pb, ZETH_R_SIZE * 8); // ZETH_R_SIZE * 8 = 48 * 8 = 384
}

template<typename FieldT>
void note_gadget<FieldT>::generate_r1cs_constraints() {
    for (size_t i = 0; i < ZETH_V_SIZE * 8; i++) {
        libsnark::generate_boolean_r1cs_constraint<FieldT>(
            this->pb,
            value[i],
            "boolean_value"
        );
    }

    for (size_t i = 0; i < ZETH_R_SIZE * 8; i++) {
        libsnark::generate_boolean_r1cs_constraint<FieldT>(
            this->pb,
            r[i],
            "boolean_value"
        );
    }
}

template<typename FieldT>
void note_gadget<FieldT>::generate_r1cs_witness(const ZethNote& note) {
    r.fill_with_bits(this->pb, get_vector_from_bits384(note.r));
    value.fill_with_bits(this->pb, get_vector_from_bits64(note.value()));
}

// Gadget that makes sure that all conditions are met in order to spend a note:
// - The nullifier is correctly computed from a_sk and rho
// - The commitment cm is correctly computed from the coin's data
// - commitment cm is in the tree of merkle root rt
template<typename HashTreeT, typename FieldT>
input_note_gadget<HashTreeT, FieldT>::input_note_gadget(libsnark::protoboard<FieldT>& pb,
                                                libsnark::pb_variable<FieldT>& ZERO,
                                                std::shared_ptr<libsnark::digest_variable<FieldT>> nullifier,
                                                libsnark::pb_variable<FieldT> rt, // merkle_root
                                                const std::string &annotation_prefix
) : note_gadget<FieldT>(pb, annotation_prefix)
{
    std::cout << "allocating stuff" << std::endl;
    a_sk.allocate(pb, ZETH_A_SK_SIZE * 8); // ZETH_A_SK_SIZE * 8 = 32 * 8 = 256
    rho.allocate(pb, ZETH_RHO_SIZE * 8); // ZETH_RHO_SIZE * 8 = 32 * 8 = 256
    address_bits_va.allocate(pb, ZETH_MERKLE_TREE_DEPTH);
    a_pk.reset(new libsnark::digest_variable<FieldT>(pb, 256, ""));
    inner_k.reset(new libsnark::digest_variable<FieldT>(pb, 256, ""));
    outer_k.reset(new libsnark::digest_variable<FieldT>(pb, 256, ""));
    commitment.reset(new libsnark::digest_variable<FieldT>(pb, 256, ""));
    field_cm.reset(new libsnark::pb_variable<FieldT>);
    (*field_cm).allocate(pb, "cm");
    libsnark::pb_variable_array<FieldT>* pb_auth_path = new libsnark::pb_variable_array<FieldT>();
    (*pb_auth_path).allocate(pb, ZETH_MERKLE_TREE_DEPTH, "authentication path");
    auth_path.reset(pb_auth_path);
    std::cout << "finish alloc" << std::endl;

    std::cout << "alloc gadgets" << std::endl;
    // Call to the "PRF_addr_a_pk_gadget" to make sure a_pk
    // is correctly computed from a_sk
    spend_authority.reset(new PRF_addr_a_pk_gadget<FieldT>(
        pb,
        ZERO,
        a_sk,
        a_pk
    ));

    // Call to the "PRF_nf_gadget" to make sure the nullifier
    // is correctly computed from a_sk and rho
    expose_nullifiers.reset(new PRF_nf_gadget<FieldT>(
        pb,
        ZERO,
        a_sk,
        rho,
        nullifier
    ));
    // Below this point, we need to do several calls
    // to the commitment gagdets.
    //
    // Call to the "note_commitment_gadget" to make sure that the
    // commitment cm is computed correctly from the coin data
    // ie: a_pk, value, rho, and trap_r#include "circuits/notes/note.tcc"

    // These gadgets compute the commitment cm (coin commitment)
    //
    // TODO: Factorize the 2 gadgets to compute k into a single gadget
    //
    // Note: In our case it can be useful to retrieve the commitment k if we want to
    // implement the mint function the same way as it is done in Zerocash.
    // That way we only need to provide k along with the value when we deposit
    // onto the mixer. Doing so removes the need to generate a proof when we deposit
    // However, this comes with a drawback of introducing different types of function calls
    // on the smart contract and also requires additional steps/function calls to "pour"/split
    // the newly created commitment corresponding to a coin of value V, into a set of commitments
    // corresponding to coins of value v_i such that Sum_i coins.value = V (ie: this step provides
    // an additional layer of obfuscation and minimizes the interactions with the mixer (that we know
    // affect the public state and leak data)).
    commit_to_inputs_inner_k.reset(new COMM_inner_k_gadget<FieldT>(
        pb,
        ZERO,
        a_pk->bits,
        rho,
        inner_k
    ));
    commit_to_inputs_outer_k.reset(new COMM_outer_k_gadget<FieldT>(
        pb,
        ZERO,
        this->r,
        inner_k->bits,
        outer_k
    ));
    commit_to_inputs_cm.reset(new COMM_cm_gadget<FieldT>(
        pb,
        ZERO,
        outer_k->bits,
        this->value,
        commitment
    ));

    // We do not forget to allocate the `value_enforce` variable
    // since it is submitted to boolean constraints
    value_enforce.allocate(pb);
    // These gadgets make sure that the computed
    // commitment is in the merkle tree of root rt
    std::cout << "alloc bit to field" << std::endl;
    bits_to_field.reset( new libsnark::packing_gadget<FieldT>(
        pb,
        commitment->bits,
        *field_cm,
        "cm bits to field"
    ));

    std::cout << "alloc auth" << std::endl;
    check_membership.reset(new merkle_path_authenticator<MiMC_hash_gadget<FieldT>, FieldT>(
        pb,
        ZETH_MERKLE_TREE_DEPTH,
        address_bits_va,
        *field_cm,
        rt,
        *auth_path,
        value_enforce,
        "auth_path"
    ));

}

template<typename HashTreeT, typename FieldT>
void input_note_gadget<HashTreeT, FieldT>::generate_r1cs_constraints() {
    // Generate constraints of parent gadget
    note_gadget<FieldT>::generate_r1cs_constraints();

    // Generate the constraints for the a_sk 256-bit string
    for (size_t i = 0; i < ZETH_A_SK_SIZE * 8; i++) { // ZETH_A_SK_SIZE * 8 = 32 * 8 = 256
        libsnark::generate_boolean_r1cs_constraint<FieldT>(
            this->pb,
            a_sk[i],
            "a_sk"
        );
    }
    // Generate the constraints for the rho 256-bit string
    for (size_t i = 0; i < ZETH_RHO_SIZE * 8; i++) { // ZETH_RHO_SIZE * 8 = 32 * 8 = 256
        libsnark::generate_boolean_r1cs_constraint<FieldT>(
            this->pb,
            rho[i],
            "rho"
        );
    }
    spend_authority->generate_r1cs_constraints();
    expose_nullifiers->generate_r1cs_constraints();
    commit_to_inputs_inner_k->generate_r1cs_constraints();
    commit_to_inputs_outer_k->generate_r1cs_constraints();
    commit_to_inputs_cm->generate_r1cs_constraints();
    // value * (1 - enforce) = 0
    // Given `enforce` is boolean constrained:
    // If `value` is zero, `enforce` _can_ be zero.
    // If `value` is nonzero, `enforce` _must_ be one.
    libsnark::generate_boolean_r1cs_constraint<FieldT>(this->pb, value_enforce, "value_enforce");
    this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(
            packed_addition(this->value),
            (1 - value_enforce),
            0
        ),
        FMT(this->annotation_prefix, " wrap_constraint_mkpath_dummy_inputs")
    );
    bits_to_field->generate_r1cs_constraints(true);
    check_membership->generate_r1cs_constraints();
}

template<typename HashTreeT, typename FieldT>
void input_note_gadget<HashTreeT, FieldT>::generate_r1cs_witness(
    std::vector<FieldT> merkle_path,
    size_t address,
    libff::bit_vector address_bits,
    const bits256 a_sk_in,
    const ZethNote& note
) {
    // Generate witness of parent gadget
    note_gadget<FieldT>::generate_r1cs_witness(note);

    // Witness a_sk for the input
    a_sk.fill_with_bits(
        this->pb,
        get_vector_from_bits256(a_sk_in)
    );

    // Witness a_pk for a_sk with PRF_addr
    spend_authority->generate_r1cs_witness();

    // [SANITY CHECK] Witness a_pk with note information
    // a_pk->bits.fill_with_bits(
    //    this->pb,
    //    get_vector_from_bits256(note.a_pk)
    // );

    // Witness rho for the input note
    rho.fill_with_bits(
        this->pb,
        get_vector_from_bits256(note.rho)
    );
    // Witness the nullifier for the input note
    expose_nullifiers->generate_r1cs_witness();

    // Witness the commitment of the input note
    commit_to_inputs_inner_k->generate_r1cs_witness();
    commit_to_inputs_outer_k->generate_r1cs_witness();
    commit_to_inputs_cm->generate_r1cs_witness();
    std::cout << "comp bit cm: "<< std::endl;
    for (size_t i = 0; i < commitment->digest_size; i++)
    {
        std::cout << this->pb.val(commitment->bits[i]);
    }
    

    //// [SANITY CHECK] Ensure the commitment is valid.
    ////commitment->bits.fill_with_bits(
    ////    this->pb,
    ////    get_vector_from_bits256(note.cm)
    ////);

    // Set enforce flag for nonzero input value
    // Set the enforce flag according to the value of the note
    // Remember that if the note has a value of 0, we do not enforce the corresponding
    // commitment to be in the tree. If the value is > 0 though, we enforce
    // the corresponding commitment to be in the merkle tree of commitment
    //
    // Note: We need to set the value of `value_enforce`, because this bit is used in the
    // merkle_tree_check_read_gadget which uses a `field_vector_copy_gadget` that does a
    // check with the computed root and the root given to the `merkle_tree_check_read_gadget`
    //
    // This check is in the form of constraints like:
    // ```
    // template<typename FieldT>
    // void field_vector_copy_gadget<FieldT>::generate_r1cs_constraints(){
    //      for (size_t i = 0; i < source.size(); ++i)
    //      {
    //          this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(do_copy, source[i] - target[i], 0),
    //                                 FMT(this->annotation_prefix, " copying_check_%zu", i));
    //      }
    //  }
    // ```
    // If `do_copy` is set to 0, we basically do NOT compare the computed root and the given root.
    // This is useful in our case as we can use any random merkle path with our dummy/0-valued coin
    // and make sure that the computed root is never compared  with the actual root (because they will never be
    // equal as we used a random merkle path to witness the 0-valued coin)
    //
    // Basically `value_enforce` makes sure that we give a VALID merkle auth path to our commitment
    // or, in other words, that the commitment is in the tree.
    //
    // The `value_enforce` is NOT set by the gagdet, it is set by us to tell whether we want to
    // verify the commitment is in the tree or whether we want to render this check useless by having
    // a tautology (ie: 0 = 0 for each constraints of the field_vector_copy_gadget)
    //
    // UPDATE:
    // The way the variable `value_enforce` works here is that: we give a root as input to the
    // `merkle_tree_check_read_gadget`. This gadget computes the root obtained by the verification
    // of the merkle authentication path and stores the result in `computed_root` which is a
    // digest variable.
    // Then, the value of the `value_enforce` or `read_successful` variable is checked to
    // copy the result of the `computed_root` IN the variable `root` which is the given root
    // If the value of `value_enforce` is FieldT::one() => the content of `root` is replaced
    // by the content of `computed_root`. Else (if `value_enforce == FieldT::zero()`), then
    // the value of `root` remains the same.
    //
    // Note that if the given path is not an auth path to the given commitment, and if the
    // value of `value_enforce` is set to FieldT::one(), then the value of `root` is changed
    // to the value of the computed root. But because the merkle root is a public
    // input, it is sent to the verifier. Thus, if the auth path is not valid, the verifier
    // gets the root value `root`, but this value is replaced by `computed_root` in the
    // circuit, which should lead the verification of the proof to fail.
    //
    // WARNING: Because we decide to use a single root for ALL the inputs of the JoinSplit
    // here, we need to be extra careful. Note that if one of the input oes not have a valid
    // auth path (is not correctly authenticated), the root (shared by all inputs)
    // will be changed and the proof should be rejected.
    this->pb.val(value_enforce) = (note.is_zero_valued()) ? FieldT::zero() : FieldT::one();

    std::cout << "[DEBUG] Value of `value_enforce`: " << this->pb.val(value_enforce) << std::endl;
    // Witness merkle tree authentication path
    address_bits_va.fill_with_bits(this->pb, address_bits);
    // Make sure `address_bits` and `address` represent the same
    // value encoded on different bases (binary and decimal)
    assert(address_bits_va.get_field_element_from_bits(pb).as_ulong() == address);
    bits_to_field->generate_r1cs_witness_from_bits();
    std::cout << "comp field cm: " << this->pb.val(*field_cm) << std::endl;
    check_membership->generate_r1cs_witness();
    std::cout << "Computed root: " << this->pb.val(check_membership->result()) << std::endl;
}

// Commit to the output notes of the JS
template<typename FieldT>
output_note_gadget<FieldT>::output_note_gadget(libsnark::protoboard<FieldT>& pb,
                                            libsnark::pb_variable<FieldT>& ZERO,
                                            std::shared_ptr<libsnark::digest_variable<FieldT>> commitment,
                                            const std::string &annotation_prefix
) : note_gadget<FieldT>(pb, annotation_prefix)
{
    rho.allocate(pb, 256);
    a_pk.reset(new libsnark::digest_variable<FieldT>(pb, 256, "a_pk"));
    inner_k.reset(new libsnark::digest_variable<FieldT>(pb, 256, "inner_k"));
    outer_k.reset(new libsnark::digest_variable<FieldT>(pb, 256, "outer_k"));
    // Commit to the output notes publicly without disclosing them.
    commit_to_outputs_inner_k.reset(new COMM_inner_k_gadget<FieldT>(
        pb,
        ZERO,
        a_pk->bits,
        rho,
        inner_k
    ));
    commit_to_outputs_outer_k.reset(new COMM_outer_k_gadget<FieldT>(
        pb,
        ZERO,
        this->r,
        inner_k->bits,
        outer_k
    ));
    commit_to_outputs_cm.reset(new COMM_cm_gadget<FieldT>(
        pb,
        ZERO,
        outer_k->bits,
        this->value,
        commitment
    ));
}


template<typename FieldT>
void output_note_gadget<FieldT>::generate_r1cs_constraints() {
    // Generate constraints of the parent gadget
    note_gadget<FieldT>::generate_r1cs_constraints();

    a_pk->generate_r1cs_constraints();
    commit_to_outputs_inner_k->generate_r1cs_constraints();
    commit_to_outputs_outer_k->generate_r1cs_constraints();
    commit_to_outputs_cm->generate_r1cs_constraints();
}

template<typename FieldT>
void output_note_gadget<FieldT>::generate_r1cs_witness(const ZethNote& note) {
    // Generate witness of the parent gadget
    note_gadget<FieldT>::generate_r1cs_witness(note);

    // Witness rho with the note information
    rho.fill_with_bits(
        this->pb,
        get_vector_from_bits256(note.rho)
    );

    // Witness a_pk with note information
    a_pk->bits.fill_with_bits(
        this->pb,
        get_vector_from_bits256(note.a_pk)
    );

    commit_to_outputs_inner_k->generate_r1cs_witness();
    commit_to_outputs_outer_k->generate_r1cs_witness();
    commit_to_outputs_cm->generate_r1cs_witness();
}

} // libzeth

#endif // __ZETH_NOTES_CIRCUITS_TCC__
