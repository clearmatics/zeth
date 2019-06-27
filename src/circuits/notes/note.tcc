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
    value.allocate(pb, "v"); 
    r_trap.allocate(pb, "r_trap");
    r_mask.allocate(pb, "r_mask");
}

template<typename FieldT>
void note_gadget<FieldT>::generate_r1cs_constraints() {
    // We may want here to constraint the value: value < v_max
}

template<typename FieldT>
void note_gadget<FieldT>::generate_r1cs_witness(const FZethNote<FieldT>& note) {
    this->pb.val(r_trap) = note.r;
    this->pb.val(r_mask) = note.r_mask;
    this->pb.val(value) = note.value();
}

// Gadget that makes sure that all conditions are met in order to spend a note:
// - The nullifier is correctly computed from a_sk and rho
// - The commitment cm is correctly computed from the coin's data
// - commitment cm is in the tree of merkle root rt
template<typename HashT, typename FieldT>
input_note_gadget<HashT, FieldT>::input_note_gadget(libsnark::protoboard<FieldT>& pb,
                                                std::shared_ptr<libsnark::pb_variable<FieldT>> nullifier,
                                                libsnark::pb_variable<FieldT> rt,                           // Expected merkle_root
                                                const std::string &annotation_prefix
) : note_gadget<FieldT>(pb, annotation_prefix)
{
    // Allocates a_sk and a_pk
    a_sk.allocate(pb, "a_sk");
    a_pk.reset(new libsnark::pb_variable<FieldT>);
    (*a_pk).allocate(pb, "a_pk");

    // Allocates rho and set the nullifier   
    rho.allocate(pb, "rho");
    nf = nullifier;

    // Allocates the address bits and the commitment
    address_bits_va.allocate(pb, ZETH_MERKLE_TREE_DEPTH);
    cm.reset(new libsnark::pb_variable<FieldT>);
    (*cm).allocate(pb, "cm");

    // Call to the "PRF_addr_a_pk_gadget" to make sure a_pk
    // is correctly computed from a_sk
    spend_authority.reset(new PRF_addr_a_pk_gadget<FieldT>(
        pb,
        a_sk
    ));

    // Call to the "PRF_nf_gadget" to make sure the nullifier
    // is correctly computed from a_sk and rho
    expose_nullifiers.reset(new PRF_nf_gadget<FieldT>(
        pb,
        a_sk,
        rho
    ));

    // Call to the "note_commitment_gadget" to make sure that the
    // commitment cm is computed correctly from the coin data
    // ie: a_pk, value, rho, and trap_r#include "circuits/notes/note.tcc"
    
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

    // This gadget compute the commitment cm (coin commitment)
    commit_to_inputs_cm.reset(new cm_gadget<FieldT>(
        pb,
        *a_pk,
        rho,
        this->r_trap,
        this->r_mask,
        this->value
    ));

    // We do not forget to allocate the `value_enforce` variable
    // since it is submitted to boolean constraints
    value_enforce.allocate(pb);

    // This gadget makes sure that the computed
    // commitment is in the merkle tree of root rt
    libsnark::pb_variable_array<FieldT>* pb_auth_path = new libsnark::pb_variable_array<FieldT>();
    (*pb_auth_path).allocate(pb, ZETH_MERKLE_TREE_DEPTH, "authentication path");
    auth_path.reset(pb_auth_path);
    check_membership.reset(new merkle_path_authenticator<MiMC_hash_gadget<FieldT>, FieldT>(
        pb,
        ZETH_MERKLE_TREE_DEPTH,
        address_bits_va,
        *cm,
        rt,
        *auth_path,
        value_enforce,
        "auth_path"        
    ));
}

template<typename HashT, typename FieldT>
void input_note_gadget<HashT, FieldT>::generate_r1cs_constraints() {

    // Generates constraints of parent gadget
    note_gadget<FieldT>::generate_r1cs_constraints();

    // Generates constraints of the a_pk gadget
    spend_authority->generate_r1cs_constraints();

    // Generates constraints of nf gadget
    expose_nullifiers->generate_r1cs_constraints();

    // Generates constraints of cm gadget
    commit_to_inputs_cm->generate_r1cs_constraints();
    
    // value * (1 - enforce) = 0
    // Given `enforce` is boolean constrained:
    // If `value` is zero, `enforce` _can_ be zero.
    // If `value` is nonzero, `enforce` _must_ be one.
    libsnark::generate_boolean_r1cs_constraint<FieldT>(this->pb, value_enforce, "value_enforce");
    this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(
            this->value,
            (1 - value_enforce),
            0
        ),
        FMT(this->annotation_prefix, " wrap_constraint_mkpath_dummy_inputs")
    );

    // Generates constraints to check membership of the commitment
    check_membership->generate_r1cs_constraints();
}

template<typename HashT, typename FieldT>
void input_note_gadget<HashT, FieldT>::generate_r1cs_witness(
    const std::vector<FieldT> path,
    const libff::bit_vector address_bits,
    const FieldT a_sk_in,
    const FZethNote<FieldT>& note
) {

    // [SANITY CHECK] Witness a_pk with note information
    this->pb.val(*a_pk) = note.a_pk;

    // Witness rho for the input note
    this->pb.val(rho) = note.rho;

    // Witness a_sk for the input
    this->pb.val(a_sk) = a_sk_in;

    // Generate witness of parent gadget
    note_gadget<FieldT>::generate_r1cs_witness(note);

    // Witness a_pk for a_sk with PRF_addr
    spend_authority->generate_r1cs_witness();

    // Witness the nullifier for the input note and fill nf's value
    expose_nullifiers->generate_r1cs_witness();
    this->pb.val(*nf) = this->pb.val(expose_nullifiers->result());

    // Witness the commitment of the input note and fill cm's value
    commit_to_inputs_cm->generate_r1cs_witness();
    this->pb.val(*cm) = this->pb.val(commit_to_inputs_cm->result());

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

    // Set address_bits_va values
    address_bits_va.fill_with_bits(this->pb, address_bits); 

    // Set value_enforce value
    this->pb.val(value_enforce) = (note.is_zero_valued()) ? FieldT::zero() : FieldT::one();
    std::cout << "[DEBUG] Value of `value_enforce`: " << this->pb.val(value_enforce) << std::endl;

    // Set auth_path values
    auth_path->fill_with_field_elements(this->pb, path);

    // Witness merkle tree authentication path
    check_membership->generate_r1cs_witness();
}

template<typename HashT, typename FieldT>
libsnark::pb_variable<FieldT> input_note_gadget<HashT, FieldT>::get_a_pk() const {
    return (*spend_authority).result();
}

template<typename HashT, typename FieldT>
libsnark::pb_variable<FieldT> input_note_gadget<HashT, FieldT>::get_nf() const {
    return (*expose_nullifiers).result();
}


// Commit to the output notes of the JS
template<typename FieldT>
output_note_gadget<FieldT>::output_note_gadget(libsnark::protoboard<FieldT>& pb,
                                            std::shared_ptr<libsnark::pb_variable<FieldT>> commitment,
                                            const std::string &annotation_prefix
) : note_gadget<FieldT>(pb, annotation_prefix)
{
    // Allocates rho and a_pk
    rho.allocate(pb, "rho");
    a_pk.reset(new libsnark::pb_variable<FieldT>);
    (*a_pk).allocate(pb, "a_pk");

    // Set the commitment
    cm = commitment;

    // Commit to the output notes publicly without disclosing them.
    commit_to_outputs_cm.reset(new cm_gadget<FieldT>(
        pb,
        *a_pk,
        rho,
        this->r_trap,
        this->r_mask,
        this->value
    ));
}

template<typename FieldT>
void output_note_gadget<FieldT>::generate_r1cs_constraints() {
    // Generate constraints of the parent gadget
    note_gadget<FieldT>::generate_r1cs_constraints();

    commit_to_outputs_cm->generate_r1cs_constraints();
}

template<typename FieldT>
void output_note_gadget<FieldT>::generate_r1cs_witness(const FZethNote<FieldT>& note) {
    // Generate witness of the parent gadget
    note_gadget<FieldT>::generate_r1cs_witness(note);

    // Witness rho with the note information
    this->pb.val(rho) = note.rho;

    // Witness a_pk with note information
    this->pb.val(*a_pk) = note.a_pk;

    commit_to_outputs_cm->generate_r1cs_witness();
    this->pb.val(*cm) = this->pb.val(commit_to_outputs_cm->result());
  
}

template<typename FieldT>
libsnark::pb_variable<FieldT> output_note_gadget<FieldT>::get_cm() const {

    return commit_to_outputs_cm->result();
}

} // libzeth

#endif // __ZETH_NOTES_CIRCUITS_TCC__
