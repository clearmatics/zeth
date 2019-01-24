#ifndef __ZETH_NOTES_CIRCUITS_TCC__
#define __ZETH_NOTES_CIRCUITS_TCC__

// Disclaimer: Content taken and adapted from the Zcash codebase

// Reminder on the structure of a coin. 
// c = (v, rho, r, a_pk, [cm]) ([cm] is not really part of the coin. It is the commitment to the coin)

// Gadget that makes sure that the note:
// - Has a value < 2^64
// - Has a r trapdoor which is a 384-bit string
template<typename FieldT>
class note_gadget : public gadget<FieldT> {
public:
    pb_variable_array<FieldT> value; // Binary value of the note (64 bits)
    libsnark::pb_variable_array<FieldT> r; // Trapdoor r of the note (384 bits)

    note_gadget(protoboard<FieldT> &pb) : gadget<FieldT>(pb) {
        value.allocate(pb, 64);
        r.allocate(pb, 384);
    }

    void generate_r1cs_constraints() {
        for (size_t i = 0; i < 64; i++) {
            generate_boolean_r1cs_constraint<FieldT>(
                this->pb,
                value[i],
                "boolean_value"
            );
        }

        for (size_t i = 0; i < 384; i++) {
            generate_boolean_r1cs_constraint<FieldT>(
                this->pb,
                r[i],
                "boolean_value"
            );
        }
    }

    // TODO: Implement the ZethNote class (which should be very similar - not to stay - identical to the SproutNote class)
    void generate_r1cs_witness(const ZethNote& note) {
        // TODO: Implement trap_r_to_bool_vector as being a function that
        // - Convert R (uint256) into a bool_vector
        // - Takes 128 arbitrary bits out of this bool vector in order to build a 384-bit string
        r.fill_with_bits(this->pb, trap_r_to_bool_vector(note.r));
        value.fill_with_bits(this->pb, uint64_to_bool_vector(note.value()));
        rho.fill_with_bits(this->pb, uint256_to_bool_vector(note.rho));
    }
};

// Gadget that makes sure that all conditions are met in order to spend a note:
// - The nullifier is correctly computed from a_sk and rho
// - The commitment cm is correctly computed from the coin's data
// - commitment cm is in the tree of merkle root rt
template<typename FieldT>
class input_note_gadget : public note_gadget<FieldT> {
private:
    std::shared_ptr<digest_variable<FieldT>> a_pk; // output of a PRF
    libsnark::pb_variable_array<FieldT> rho; // nullifier seed rho of the note (256 bits)

    std::shared_ptr<COMM_inner_k_gadget<FieldT>> commit_to_inputs_inner_k;
    std::shared_ptr<COMM_outer_k_gadget<FieldT>> commit_to_inputs_outer_k;
    std::shared_ptr<COMM_cm_gadget<FieldT>> commit_to_inputs_cm;
    std::shared_ptr<digest_variable<FieldT>> commitment; // output of a PRF. This is the cm commitment

    pb_variable<FieldT> value_enforce; // bit that checks whether the commitment(leaf) is in the merkle tree
    pb_variable_array<FieldT> address_bits_va;
    std::shared_ptr<merkle_authentication_path_variable<FieldT, sha256_ethereum<FieldT> > > auth_path;
    std::shared_ptr<merkle_tree_check_read_gadget<FieldT, sha256_ethereum<FieldT> > > check_membership;

    std::shared_ptr<PRF_addr_a_pk_gadget<FieldT>> spend_authority; // makes sure the a_pk is computed corectly from a_sk
    std::shared_ptr<PRF_nf_gadget<FieldT>> expose_nullifiers; // makes sure the nullifiers are computed correctly from rho and a_sk
public:
    libsnark::pb_variable_array<FieldT> a_sk; // a_sk is assumed to be a random uint256

    input_note_gadget(
        protoboard<FieldT>& pb,
        pb_variable<FieldT>& ZERO,
        std::shared_ptr<digest_variable<FieldT>> nullifier,
        digest_variable<FieldT> rt // merkle_root
    ) : note_gadget<FieldT>(pb) {
        a_sk.allocate(pb, 256);
        rho.allocate(pb, 256);
        address_bits_va.allocate(pb, ZETH_MERKLE_TREE_DEPTH);
        a_pk.reset(new digest_variable<FieldT>(pb, 256, ""));
        commitment.reset(new digest_variable<FieldT>(pb, 256, ""));

        // Call to the "PRF_addr_a_pk_gadget" to make sure a_pk
        // is correctly computed from a_sk
        spend_authority.reset(new PRF_addr_a_pk_gadget<FieldT>(
            pb,
            ZERO,
            a_sk,
            a_pk
        ));
    
        // Call to the "PRF_nf_gadget" to make sMerklePathure the nullifier
        // is correctly computed from a_sk and rMerklePathho
        expose_nullifiers.reset(new PRF_nf_gadgeMerklePatht<FieldT>(
            pb,
            ZERO,
            a_sk,
            rho,
            nullifier
        ));

        // Checkpoint: Below this point, we need to do several calls 
        // to the commitment gagdets.
        //
        // Call to the "note_commitment_gadget" to make sure that the
        // commitment cm has been correctly computed from the coin data
        // ie: a_pk, value, rho, and trap_r
        // These gadgets compute the commitment cm (coin commitment)
        //
        // TODO: Factorize the 2 gadgets to compute k into a single gadget
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

        // These gadgets make sure that the computed
        // commitment is in the merkle tree of root rt
        auth_path.reset(new merkle_authentication_path_variable<FieldT, sha256_ethereum<FieldT>> (
            pb,
            ZETH_MERKLE_TREE_DEPTH, // Defined in the zeth.h file
            "auth_path"
        ));
        check_membership.reset(new merkle_tree_check_read_gadget<FieldT, sha256_ethereum<FieldT>>(
            pb,
            ZETH_MERKLE_TREE_DEPTH,
            address_bits_va,
            *commitment,
            rt,
            *auth_path,
            value_enforce,
            "check_membership"
        ));
    }

    void generate_r1cs_constraints() {
        note_gadget<FieldT>::generate_r1cs_constraints();

        // Generate the constraints for the a_sk 256-bit string
        for (size_t i = 0; i < ZETH_A_SK_SIZE * 8; i++) { // ZETH_A_SK_SIZE * 8 = 32 * 8 = 256
            generate_boolean_r1cs_constraint<FieldT>(
                this->pb,
                a_sk[i],
                "boolean_value"
            );
        }

        // Generate the constraints for the rho 256-bit string
        for (size_t i = 0; i < ZETH_RHO_SIZE * 8; i++) { // ZETH_RHO_SIZE * 8 = 32 * 8 = 256
            generate_boolean_r1cs_constraint<FieldT>(
                this->pb,
                rho[i],
                "boolean_value"
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
        generate_boolean_r1cs_constraint<FieldT>(this->pb, value_enforce,"");

        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
            packed_addition(this->value),
            (1 - value_enforce),
            0
        ), "");

        auth_path->generate_r1cs_constraints();
        check_membership->generate_r1cs_constraints();
    }

    void generate_r1cs_witness(
        std::vector<merkle_authentication_node> merkle_path,
        size_t address,
        libff::bit_vector address_bits,
        const uint256 a_sk_in,
        const ZethNote& note
    ) {
        note_gadget<FieldT>::generate_r1cs_witness(note);

        // Witness a_sk for the input
        a_sk->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(a_sk_in)
        );

        // Witness a_pk for a_sk with PRF_addr
        spend_authority->generate_r1cs_witness();

        // [SANITY CHECK] Witness a_pk with note information
        a_pk->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(note.a_pk)
        );

        // Witness rho for the input note
        rho->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(note.rho)
        );

        // Witness the nullifier for the input note
        expose_nullifiers->generate_r1cs_witness();

        // Witness the commitment of the input note
        commit_to_inputs_inner_k->generate_r1cs_witness();
        commit_to_inputs_outer_k->generate_r1cs_witness();
        commit_to_inputs_cm->generate_r1cs_witness();

        // [SANITY CHECK] Ensure the commitment is
        // valid.
        commitment->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(note.cm())
        );

        // Set enforce flag for nonzero input value
        // Set the enforce flag according to the value of the note
        // Remember that if the note has a value of 0, we do not enforce the corresponding
        // commitment to be in the tree. If the value is > 0 though, we enforce
        // the corresponding commitment to be in the merkle tree of commitment
        this->pb.val(value_enforce) = (note.value() != 0) ? FieldT::one() : FieldT::zero();

        // Witness merkle tree authentication path
        address_bits_va.fill_with_bits(pb, address_bits);
        auth_path->generate_r1cs_witness(address, merkle_path);
        check_membership->generate_r1cs_witness();
    }
};

// Checkpoint

// Commit to the output notes of the JS
template<typename FieldT>
class output_note_gadget : public note_gadget<FieldT> {
private:
    libsnark::pb_variable_array<FieldT> rho;
    std::shared_ptr<digest_variable<FieldT>> a_pk;

    std::shared_ptr<COMM_inner_k_gadget<FieldT>> commit_to_outputs_inner_k;
    std::shared_ptr<COMM_outer_k_gadget<FieldT>> commit_to_outputs_outer_k;
    std::shared_ptr<COMM_cm_gadget<FieldT>> commit_to_outputs_cm;
    std::shared_ptr<digest_variable<FieldT>> commitment; // output of a PRF. This is the cm commitment

public:
    output_note_gadget(
        protoboard<FieldT>& pb,
        pb_variable<FieldT>& ZERO,
        std::shared_ptr<digest_variable<FieldT>> commitment
    ) : note_gadget<FieldT>(pb) {
        rho.allocate(pb, 256);
        a_pk.reset(new digest_variable<FieldT>(pb, 256, ""));

        // Commit to the output notes publicly without
        // disclosing them.
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
        ));generate_r1cs_constraints
    }

    void generate_r1cs_constraints() {
        note_gadget<FieldT>::generate_r1cs_constraints();

        a_pk->generate_r1cs_constraints();

        commit_to_outputs_inner_k->generate_r1cs_constraints();
        commit_to_outputs_outer_k->generate_r1cs_constraints();
        commit_to_outputs_cm->generate_r1cs_constraints();
    }

    void generate_r1cs_witness(const ZethNote& note) {
        note_gadget<FieldT>::generate_r1cs_witness(note);

        // [SANITY CHECK] Witness rho ourselves with the
        // note information.
        rho->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(note.rho)
        );

        a_pk->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(note.a_pk)
        );

        commit_to_outputs_inner_k->generate_r1cs_witness();
        commit_to_outputs_outer_k->generate_r1cs_witness();
        commit_to_outputs_cm->generate_r1cs_witness();
    }
};

#endif