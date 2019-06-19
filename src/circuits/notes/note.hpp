#ifndef __ZETH_NOTES_CIRCUITS_HPP__
#define __ZETH_NOTES_CIRCUITS_HPP__

// DISCLAIMER: 
// Content Taken and adapted from Zcash
// https://github.com/zcash/zcash/blob/master/src/zcash/circuit/note.tcc

#include <src/circuits/merkle_tree/merkle_path_authenticator.hpp>

// Get the prfs and commitments circuits
#include "circuits/prfs/prfs.hpp"
#include "circuits/commitments/commitments.hpp"
// Get the utils functions
#include "circuits/circuits-util.tcc"

// Get the bits typedefs and associated functions
#include "types/bits.hpp"
// Get the ZethNote class
#include "types/note.hpp"

namespace libzeth {

// Gadget that makes sure that the note:
// - Has a value < 2^64
// - Has a valid r trapdoor which is a 384-bit string
template<typename FieldT>
class note_gadget : public libsnark::gadget<FieldT> {
public:
    libsnark::pb_variable<FieldT> value; // Binary value of the note (64 bits)
    libsnark::pb_variable<FieldT> r; // Trapdoor r of the note (384 bits)
    libsnark::pb_variable<FieldT> r_mask; // Trapdoor r of the note (384 bits)
    libsnark::pb_variable<FieldT> masked; // Masked inner commitment


    note_gadget(libsnark::protoboard<FieldT> &pb, 
                const std::string &annotation_prefix = "base_note_gadget");
    void generate_r1cs_constraints();
    void generate_r1cs_witness(const FZethNote& note);
};

// Gadget that makes sure that all conditions are met in order to spend a note:
// - The nullifier is correctly computed from a_sk and rho
// - The commitment cm is correctly computed from the coin's data
// - commitment cm is in the tree of merkle root rt
template<typename FieldT>
class input_note_gadget : public note_gadget<FieldT> {
private:
    std::shared_ptr<libsnark::pb_variable<FieldT>> a_pk; // Output of a PRF
    libsnark::pb_variable<FieldT> rho; // Nullifier seed 

    std::shared_ptr<COMM_inner_k_gadget<FieldT>> commit_to_inputs_inner_k;
    std::shared_ptr<libsnark::pb_variable<FieldT>> inner_k;
    std::shared_ptr<COMM_outer_k_gadget<FieldT>> commit_to_inputs_outer_k;
    std::shared_ptr<libsnark::pb_variable<FieldT>> outer_k;
    std::shared_ptr<COMM_cm_gadget<FieldT>> commit_to_inputs_cm;
    std::shared_ptr<libsnark::pb_variable<FieldT>> commitment; // Output of a PRF. This is the note commitment

    libsnark::pb_variable<FieldT> value_enforce; // Bit that checks whether the commitment (leaf) has to be found in the merkle tree (Necessary to support dummy notes of value 0)
    libsnark::pb_variable_array<FieldT> address_bits;
    std::shared_ptr<libsnark::merkle_path_authenticator<MiMC_hash_gadget<FieldT> , FieldT> > auth_path;

    std::shared_ptr<PRF_addr_a_pk_gadget<FieldT>> spend_authority; // Makes sure the a_pk is computed corectly from a_sk
    std::shared_ptr<PRF_nf_gadget<FieldT>> expose_nullifiers; // Makes sure the nullifiers are computed correctly from rho and a_sk
public:
    libsnark::pb_variable<FieldT> a_sk; // a_sk is assumed to be a random uint256

    input_note_gadget(libsnark::protoboard<FieldT>& pb,
                    std::shared_ptr<libsnark::pb_variable<FieldT>> nullifier,
                    libsnark::pb_variable<FieldT> rt, // merkle_root
                    const std::string &annotation_prefix = "input_note_gadget");
    void generate_r1cs_constraints();
    void generate_r1cs_witness(const libsnark::pb_variable_array<FieldT> path,
                            const libsnark::pb_variable_array<FieldT> address_bits,
                            const FieldT a_sk_in,
                            const FZethNote& note);
};

// Commit to the output notes of the JS
template<typename FieldT>
class output_note_gadget : public note_gadget<FieldT> {
private:
    libsnark::pb_variable<FieldT> rho;
    std::shared_ptr<libsnark::pb_variable<FieldT>> a_pk;

    std::shared_ptr<COMM_inner_k_gadget<FieldT>> commit_to_outputs_inner_k;
    std::shared_ptr<libsnark::pb_variable<FieldT>> inner_k;
    std::shared_ptr<COMM_outer_k_gadget<FieldT>> commit_to_outputs_outer_k;
    std::shared_ptr<libsnark::pb_variable<FieldT>> outer_k;
    std::shared_ptr<COMM_cm_gadget<FieldT>> commit_to_outputs_cm;
    //std::shared_ptr<libsnark::pb_variable<FieldT>> commitment; // output of a PRF. This is the cm commitment

public:
    output_note_gadget(
        libsnark::protoboard<FieldT>& pb,
        std::shared_ptr<libsnark::pb_variable<FieldT>> commitment,
        const std::string &annotation_prefix = "output_note_gadget");
    void generate_r1cs_constraints();
    void generate_r1cs_witness(const FZethNote& note);
};

} // libzeth
#include "circuits/notes/note.tcc"

#endif // __ZETH_NOTES_CIRCUITS_HPP__