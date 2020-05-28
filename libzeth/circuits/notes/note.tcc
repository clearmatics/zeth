#ifndef __ZETH_CIRCUITS_NOTE_TCC__
#define __ZETH_CIRCUITS_NOTE_TCC__

// DISCLAIMER:
// Content Taken and adapted from Zcash
// https://github.com/zcash/zcash/blob/master/src/zcash/circuit/note.tcc

#include "libzeth/circuits/notes/note.hpp"

namespace libzeth
{

template<typename FieldT>
note_gadget<FieldT>::note_gadget(
    libsnark::protoboard<FieldT> &pb, const std::string &annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix)
{
    value.allocate(
        pb,
        ZETH_V_SIZE,
        FMT(this->annotation_prefix, " value")); // ZETH_V_SIZE = 64
    r.allocate(
        pb,
        ZETH_R_SIZE,
        FMT(this->annotation_prefix, " r")); // ZETH_R_SIZE = 256
}

template<typename FieldT> void note_gadget<FieldT>::generate_r1cs_constraints()
{
    for (size_t i = 0; i < ZETH_V_SIZE; i++) {
        libsnark::generate_boolean_r1cs_constraint<FieldT>(
            this->pb, value[i], FMT(this->annotation_prefix, " value[%zu]", i));
    }

    for (size_t i = 0; i < ZETH_R_SIZE; i++) {
        libsnark::generate_boolean_r1cs_constraint<FieldT>(
            this->pb, r[i], FMT(this->annotation_prefix, " r[%zu]", i));
    }
}

template<typename FieldT>
void note_gadget<FieldT>::generate_r1cs_witness(const zeth_note &note)
{
    note.r.fill_variable_array(this->pb, r);
    note.value.fill_variable_array(this->pb, value);
}

// Gadget that makes sure that all conditions are met in order to spend a note:
// - The nullifier is correctly computed from a_sk and rho
// - The commitment cm is correctly computed from the coin's data
// - commitment cm is in the tree of merkle root rt
template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
input_note_gadget<FieldT, HashT, HashTreeT, TreeDepth>::input_note_gadget(
    libsnark::protoboard<FieldT> &pb,
    const libsnark::pb_variable<FieldT> &ZERO,
    std::shared_ptr<libsnark::digest_variable<FieldT>> a_sk,
    std::shared_ptr<libsnark::digest_variable<FieldT>> nullifier,
    const libsnark::pb_variable<FieldT> &rt,
    const std::string &annotation_prefix)
    : note_gadget<FieldT>(pb, annotation_prefix)
{
    // ZETH_RHO_SIZE = 256
    rho.allocate(pb, ZETH_RHO_SIZE, " rho");
    address_bits_va.allocate(
        pb, TreeDepth, FMT(this->annotation_prefix, " merkle_tree_depth"));
    a_pk.reset(new libsnark::digest_variable<FieldT>(
        pb, HashT::get_digest_len(), FMT(this->annotation_prefix, " a_pk")));
    commitment.allocate(pb, FMT(this->annotation_prefix, " commitment"));

    libsnark::pb_variable_array<FieldT> *pb_auth_path =
        new libsnark::pb_variable_array<FieldT>();
    pb_auth_path->allocate(
        pb, TreeDepth, FMT(this->annotation_prefix, " authentication_path"));
    auth_path.reset(pb_auth_path);

    // Call to the "PRF_addr_a_pk_gadget" to make sure a_pk is correctly
    // computed from a_sk
    spend_authority.reset(
        new PRF_addr_a_pk_gadget<FieldT, HashT>(pb, ZERO, a_sk->bits, a_pk));

    // Call to the "PRF_nf_gadget" to make sure the nullifier is correctly
    // computed from a_sk and rho
    expose_nullifiers.reset(
        new PRF_nf_gadget<FieldT, HashT>(pb, ZERO, a_sk->bits, rho, nullifier));

    // Below this point, we need to do several calls
    // to the commitment gagdets.
    //
    // Call to the "note_commitment_gadget" to make sure that the
    // commitment cm is computed correctly from the coin data
    // ie: a_pk, value, rho, and trap_r#include "circuits/notes/note.tcc"

    // This gadget compute the commitment cm (coin commitment)
    //
    // Note: In our case it can be useful to retrieve the commitment k if we
    // want to implement the mint function the same way as it is done in
    // Zerocash. That way we only need to provide k along with the value when we
    // deposit onto the mixer. Doing so removes the need to generate a proof
    // when we deposit However, this comes with a drawback of introducing
    // different types of function calls on the smart contract and also requires
    // additional steps/function calls to "pour"/split the newly created
    // commitment corresponding to a coin of value V, into a set of commitments
    // corresponding to coins of value v_i such that Sum_i coins.value = V (ie:
    // this step provides an additional layer of obfuscation and minimizes the
    // interactions with the mixer (that we know affect the public state and
    // leak data)).
    commit_to_inputs_cm.reset(new COMM_cm_gadget<FieldT, HashT>(
        pb, a_pk->bits, rho, this->r, this->value, commitment));

    // We do not forget to allocate the `value_enforce` variable
    // since it is submitted to boolean constraints
    value_enforce.allocate(pb, FMT(this->annotation_prefix, " value_enforce"));

    // This gadget makes sure that the computed
    // commitment is in the merkle tree of root rt
    // We finally compute a root from the (field) commitment and the
    // authentication path We furthermore check, depending on value_enforce, if
    // the computed root is equal to the current one
    check_membership.reset(new merkle_path_authenticator<FieldT, HashTreeT>(
        pb,
        TreeDepth,
        address_bits_va,
        commitment,
        rt,
        *auth_path,
        value_enforce, // boolean that is set to ONE if the cm needs to be in
                       // the tree of root rt (and if the given path needs to be
                       // correct), ZERO otherwise
        FMT(this->annotation_prefix, " auth_path")));
}

template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
void input_note_gadget<FieldT, HashT, HashTreeT, TreeDepth>::
    generate_r1cs_constraints()
{
    // Generate constraints of parent gadget
    note_gadget<FieldT>::generate_r1cs_constraints();

    // Generate the constraints for the rho 256-bit string
    for (size_t i = 0; i < ZETH_RHO_SIZE; i++) { // ZETH_RHO_SIZE = 256
        libsnark::generate_boolean_r1cs_constraint<FieldT>(
            this->pb, rho[i], FMT(this->annotation_prefix, " rho"));
    }
    spend_authority->generate_r1cs_constraints();
    expose_nullifiers->generate_r1cs_constraints();
    commit_to_inputs_cm->generate_r1cs_constraints();
    // value * (1 - enforce) = 0
    // Given `enforce` is boolean constrained:
    // If `value` is zero, `enforce` _can_ be zero.
    // If `value` is nonzero, `enforce` _must_ be one.
    libsnark::generate_boolean_r1cs_constraint<FieldT>(
        this->pb,
        value_enforce,
        FMT(this->annotation_prefix, " value_enforce"));

    this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(
            packed_addition(this->value), (1 - value_enforce), 0),
        FMT(this->annotation_prefix, " wrap_constraint_mkpath_dummy_inputs"));

    check_membership->generate_r1cs_constraints();
}

template<typename FieldT, typename HashT, typename HashTreeT, size_t TreeDepth>
void input_note_gadget<FieldT, HashT, HashTreeT, TreeDepth>::
    generate_r1cs_witness(
        const std::vector<FieldT> &merkle_path,
        const bits_addr<TreeDepth> &address_bits,
        const zeth_note &note)
{
    // Generate witness of parent gadget
    note_gadget<FieldT>::generate_r1cs_witness(note);

    // Witness a_pk for a_sk with PRF_addr
    spend_authority->generate_r1cs_witness();

    // Witness rho for the input note
    note.rho.fill_variable_array(this->pb, rho);
    // Witness the nullifier for the input note
    expose_nullifiers->generate_r1cs_witness();

    // Witness the commitment of the input note
    commit_to_inputs_cm->generate_r1cs_witness();

    // Set enforce flag for nonzero input value
    // Set the enforce flag according to the value of the note
    // Remember that if the note has a value of 0, we do not enforce the
    // corresponding commitment to be in the tree. If the value is > 0 though,
    // we enforce the corresponding commitment to be in the merkle tree of
    // commitment
    //
    // Note: We need to set the value of `value_enforce`, because this bit is
    // used in the merkle_tree_check_read_gadget which uses a
    // `field_vector_copy_gadget` that does a check with the computed root and
    // the root given to the `merkle_tree_check_read_gadget`
    //
    // This check is in the form of constraints like:
    // ```
    // template<typename FieldT>
    // void field_vector_copy_gadget<FieldT>::generate_r1cs_constraints(){
    //      for (size_t i = 0; i < source.size(); ++i)
    //      {
    //          this->pb.add_r1cs_constraint(
    //              r1cs_constraint<FieldT>(
    //                  do_copy,
    //                  source[i] - target[i],
    //                  0
    //              ),
    //              FMT(
    //                  this->annotation_prefix, "
    //                  copying_check_%zu", i));
    //      }
    //  }
    // ```
    // If `do_copy` is set to 0, we basically do NOT compare the computed root
    // and the given root. This is useful in our case as we can use any random
    // merkle path with our dummy/0-valued coin and make sure that the computed
    // root is never compared  with the actual root (because they will never be
    // equal as we used a random merkle path to witness the 0-valued coin)
    //
    // Basically `value_enforce` makes sure that we give a VALID merkle auth
    // path to our commitment or, in other words, that the commitment is in the
    // tree.
    //
    // The `value_enforce` is NOT set by the gagdet, it is set by us to tell
    // whether we want to verify the commitment is in the tree or whether we
    // want to render this check useless by having a tautology (ie: 0 = 0 for
    // each constraints of the field_vector_copy_gadget)
    //
    // UPDATE:
    // The way the variable `value_enforce` works here is that: we give a root
    // as input to the `merkle_tree_check_read_gadget`. This gadget computes the
    // root obtained by the verification of the merkle authentication path and
    // stores the result in `computed_root` which is a digest variable. Then,
    // the value of the `value_enforce` or `read_successful` variable is checked
    // to copy the result of the `computed_root` IN the variable `root` which is
    // the given root If the value of `value_enforce` is FieldT::one() => the
    // content of `root` is replaced by the content of `computed_root`. Else (if
    // `value_enforce == FieldT::zero()`), then the value of `root` remains the
    // same.
    //
    // Note that if the given path is not an auth path to the given commitment,
    // and if the value of `value_enforce` is set to FieldT::one(), then the
    // value of `root` is changed to the value of the computed root. But because
    // the merkle root is a public input, it is sent to the verifier. Thus, if
    // the auth path is not valid, the verifier gets the root value `root`, but
    // this value is replaced by `computed_root` in the circuit, which should
    // lead the verification of the proof to fail.
    //
    // WARNING: Because we decide to use a single root for ALL the inputs of the
    // JoinSplit here, we need to be extra careful. Note that if one of the
    // input oes not have a valid auth path (is not correctly authenticated),
    // the root (shared by all inputs) will be changed and the proof should be
    // rejected.
    this->pb.val(value_enforce) =
        (note.is_zero_valued()) ? FieldT::zero() : FieldT::one();
    std::cout << "[DEBUG] Value of `value_enforce`: "
              << (this->pb.val(value_enforce)).as_ulong() << std::endl;

    // Witness merkle tree authentication path
    address_bits.fill_variable_array(this->pb, address_bits_va);

    // Set auth_path values
    auth_path->fill_with_field_elements(this->pb, merkle_path);

    check_membership->generate_r1cs_witness();
}

// Commit to the output notes of the JS
template<typename FieldT, typename HashT>
output_note_gadget<FieldT, HashT>::output_note_gadget(
    libsnark::protoboard<FieldT> &pb,
    std::shared_ptr<libsnark::digest_variable<FieldT>> rho,
    const libsnark::pb_variable<FieldT> &commitment,
    const std::string &annotation_prefix)
    : note_gadget<FieldT>(pb, annotation_prefix)
{
    a_pk.reset(new libsnark::digest_variable<FieldT>(
        pb, HashT::get_digest_len(), FMT(this->annotation_prefix, " a_pk")));

    // Commit to the output notes publicly without disclosing them.
    commit_to_outputs_cm.reset(new COMM_cm_gadget<FieldT, HashT>(
        pb, a_pk->bits, rho->bits, this->r, this->value, commitment));
}

template<typename FieldT, typename HashT>
void output_note_gadget<FieldT, HashT>::generate_r1cs_constraints()
{
    // Generate constraints of the parent gadget
    note_gadget<FieldT>::generate_r1cs_constraints();

    a_pk->generate_r1cs_constraints();
    commit_to_outputs_cm->generate_r1cs_constraints();
}

template<typename FieldT, typename HashT>
void output_note_gadget<FieldT, HashT>::generate_r1cs_witness(
    const zeth_note &note)
{
    // Generate witness of the parent gadget
    note_gadget<FieldT>::generate_r1cs_witness(note);

    // Witness a_pk with note information
    note.a_pk.fill_variable_array(this->pb, a_pk->bits);

    commit_to_outputs_cm->generate_r1cs_witness();
}

} // namespace libzeth

#endif // __ZETH_CIRCUITS_NOTE_TCC__
