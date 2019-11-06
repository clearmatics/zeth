#ifndef __ZETH_CIRCUITS_NOTE_HPP__
#define __ZETH_CIRCUITS_NOTE_HPP__

// DISCLAIMER:
// Content Taken and adapted from Zcash
// https://github.com/zcash/zcash/blob/master/src/zcash/circuit/note.tcc

#include <src/circuits/merkle_tree/merkle_path_authenticator.hpp>

// Get the prfs and commitments circuits
#include "circuits/commitments/commitment.hpp"
#include "circuits/prfs/prf.hpp"
// Get the utils functions
#include "circuits/circuits-utils.hpp"

// Get the bits typedefs and associated functions
#include "types/bits.hpp"
// Get the zeth_note class
#include "types/note.hpp"

namespace libzeth
{

// Gadget that makes sure that the note:
// - Has a value < 2^64
// - Has a valid r trapdoor which is a 384-bit string
template<typename FieldT> class note_gadget : public libsnark::gadget<FieldT>
{
public:
    // Binary value of the note (64 bits)
    libsnark::pb_variable_array<FieldT> value;
    // Trapdoor r of the note (384 bits)
    libsnark::pb_variable_array<FieldT> r;

    note_gadget(
        libsnark::protoboard<FieldT> &pb,
        const std::string &annotation_prefix = "note_gadget");
    void generate_r1cs_constraints();
    void generate_r1cs_witness(const zeth_note &note);
};

// Gadget that makes sure that all conditions are met in order to spend a note:
// - The nullifier is correctly computed from a_sk and rho
// - The commitment cm is correctly computed from the coin's data
// - commitment cm is in the tree of merkle root rt
template<typename FieldT, typename HashT, typename HashTreeT>
class input_note_gadget : public note_gadget<FieldT>
{
private:
    // Output of a PRF (digest_variable)
    std::shared_ptr<libsnark::digest_variable<FieldT>> a_pk;
    // Nullifier seed (256 bits)
    libsnark::pb_variable_array<FieldT> rho;

    std::shared_ptr<COMM_inner_k_gadget<FieldT, HashT>>
        commit_to_inputs_inner_k;
    std::shared_ptr<libsnark::digest_variable<FieldT>> inner_k;
    std::shared_ptr<COMM_outer_k_gadget<FieldT, HashT>>
        commit_to_inputs_outer_k;
    std::shared_ptr<libsnark::digest_variable<FieldT>> outer_k;
    std::shared_ptr<COMM_cm_gadget<FieldT, HashT>> commit_to_inputs_cm;
    // Note commitment (bits), output of COMMIT gadget
    std::shared_ptr<libsnark::digest_variable<FieldT>> commitment;
    // Packing gadget to pack commitment from bits to field elements
    std::shared_ptr<libsnark::packing_gadget<FieldT>> bits_to_field;
    // Note commitment (field), input of Merkle Tree gadget
    std::shared_ptr<libsnark::pb_variable<FieldT>> field_cm;

    // Bit that checks whether the commitment (leaf) has to be found in the
    // merkle tree (Necessary to support dummy notes of value 0)
    libsnark::pb_variable<FieldT> value_enforce;
    // Address of the commitment on the tree as Field
    libsnark::pb_variable_array<FieldT> address_bits_va;
    // Authentication pass comprising of all the intermediary hash siblings from
    // the leaf to root
    std::shared_ptr<libsnark::pb_variable_array<FieldT>> auth_path;
    // Gadget computing the merkle root from a commitment and merkle path, and
    // checking whether it is the expected (i.e. current) merkle root value if
    // value_enforce=1,
    std::shared_ptr<merkle_path_authenticator<FieldT, HashTreeT>>
        check_membership;

    // Makes sure the a_pk is computed corectly from a_sk
    std::shared_ptr<PRF_addr_a_pk_gadget<FieldT, HashT>> spend_authority;
    // Makes sure the nullifiers are computed correctly from rho and a_sk
    std::shared_ptr<PRF_nf_gadget<FieldT, HashT>> expose_nullifiers;

    std::shared_ptr<libsnark::digest_variable<FieldT>> nullifier;

public:
    input_note_gadget(
        libsnark::protoboard<FieldT> &pb,
        libsnark::pb_variable<FieldT> &ZERO,
        std::shared_ptr<libsnark::digest_variable<FieldT>> a_sk,
        // Input note Nullifier
        std::shared_ptr<libsnark::digest_variable<FieldT>> nullifier,
        // Current Merkle root
        libsnark::pb_variable<FieldT> rt,
        const std::string &annotation_prefix = "input_note_gadget");
    void generate_r1cs_constraints();
    void generate_r1cs_witness(
        const std::vector<FieldT> merkle_path,
        libff::bit_vector address_bits,
        const zeth_note &note);
};

// Commit to the output notes of the JS
template<typename FieldT, typename HashT>
class output_note_gadget : public note_gadget<FieldT>
{
private:
    std::shared_ptr<libsnark::digest_variable<FieldT>> a_pk;

    std::shared_ptr<COMM_inner_k_gadget<FieldT, HashT>>
        commit_to_outputs_inner_k;
    std::shared_ptr<libsnark::digest_variable<FieldT>> inner_k;
    std::shared_ptr<COMM_outer_k_gadget<FieldT, HashT>>
        commit_to_outputs_outer_k;
    std::shared_ptr<libsnark::digest_variable<FieldT>> outer_k;
    std::shared_ptr<COMM_cm_gadget<FieldT, HashT>> commit_to_outputs_cm;

public:
    output_note_gadget(
        libsnark::protoboard<FieldT> &pb,
        libsnark::pb_variable<FieldT> &ZERO,
        std::shared_ptr<libsnark::digest_variable<FieldT>> rho,
        std::shared_ptr<libsnark::digest_variable<FieldT>> commitment,
        const std::string &annotation_prefix = "output_note_gadget");
    void generate_r1cs_constraints();
    void generate_r1cs_witness(const zeth_note &note);
};

} // namespace libzeth
#include "circuits/notes/note.tcc"

#endif // __ZETH_CIRCUITS_NOTE_HPP__