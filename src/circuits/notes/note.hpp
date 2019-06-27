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

// Get the ZethNote class
#include "types/note.hpp"

namespace libzeth {

// Wrapper gadget that makes sure that the note:
// - Has a value
// - Has a valid r trapdoor and r_mask
template<typename FieldT>
class note_gadget : public libsnark::gadget<FieldT> {
public:
    libsnark::pb_variable<FieldT> value;                                            // Value of the note
    libsnark::pb_variable<FieldT> r_trap;                                           // Trapdoor r of the note
    libsnark::pb_variable<FieldT> r_mask;                                           // Mask r of the note


    note_gadget(libsnark::protoboard<FieldT> &pb,
                const std::string &annotation_prefix = "base_note_gadget");

    void generate_r1cs_constraints();
    void generate_r1cs_witness(const ZethNote<FieldT>& note);
};

// Gadget that makes sure that all conditions are met in order to spend a note:
// - The nullifier is correctly computed from a_sk and rho
// - The commitment cm is correctly computed from the coin's data
// - commitment cm is in the tree of merkle root rt
template<typename HashT, typename FieldT>
class input_note_gadget : public note_gadget<FieldT> {
public:
    std::shared_ptr<libsnark::pb_variable<FieldT>> a_pk;                            // Public address ; output of a PRF
    libsnark::pb_variable<FieldT> rho;                                              // Nullifier seed
    std::shared_ptr<libsnark::pb_variable<FieldT>> nf;                              // Nullifier

    std::shared_ptr<cm_gadget<FieldT>> commit_to_inputs_cm;                         // Gadget computing the commitment (leaf)
    std::shared_ptr<libsnark::pb_variable<FieldT>> cm;                              // Note commitment ; output of a PRF

    libsnark::pb_variable<FieldT> value_enforce;                                    // Boolean to check whether the commitment (leaf) has to be found in the merkle tree ; necessary to support dummy notes of value 0.
    libsnark::pb_variable_array<FieldT> address_bits_va;                            // Address of the commitment (leaf) in bits

    std::shared_ptr<libsnark::pb_variable_array<FieldT>> auth_path;                 // Authentication pass comprising of all the intermediary hash siblings from the leaf to root
    std::shared_ptr<merkle_path_authenticator<HashT, FieldT> > check_membership;   // Gadget computing the merkle root from a commitment and merkle path, and checking whether it is the expected (i.e. current) merkle root value if value_enforce=1,

    std::shared_ptr<PRF_addr_a_pk_gadget<FieldT>> spend_authority;                  // Gadget making sure the a_pk is corectly computed from a_sk
    std::shared_ptr<PRF_nf_gadget<FieldT>> expose_nullifiers;                       // Gadget making sure the nullifiers are correctly computed from rho and a_sk

public:
    libsnark::pb_variable<FieldT> a_sk;                                             // Private key

    input_note_gadget(libsnark::protoboard<FieldT>& pb,
                    std::shared_ptr<libsnark::pb_variable<FieldT>> nullifier,       // Note nullifier
                    libsnark::pb_variable<FieldT> rt,                               // Expected merkle root
                    const std::string &annotation_prefix = "input_note_gadget");

    void generate_r1cs_constraints();

    void generate_r1cs_witness(const std::vector<FieldT> path,
                            const libff::bit_vector address_bits,
                            const FieldT a_sk_in,
                            const ZethNote<FieldT>& note);

    // Returns the computed a_pk
    libsnark::pb_variable<FieldT> get_a_pk() const;

    // Returns the computed nullifer nf
    libsnark::pb_variable<FieldT> get_nf() const;

};

// Commit to the output notes of the JS
template<typename FieldT>
class output_note_gadget : public note_gadget<FieldT> {
public:
    libsnark::pb_variable<FieldT> rho;                                              // Nullifier seed
    std::shared_ptr<libsnark::pb_variable<FieldT>> a_pk;                            // Public address ; output of a PRF
    std::shared_ptr<libsnark::pb_variable<FieldT>> cm;                              // Note commitment
    std::shared_ptr<cm_gadget<FieldT>> commit_to_outputs_cm;                        // Gadget computing the commitment (leaf)

    //std::shared_ptr<libsnark::pb_variable<FieldT>> commitment; // output of a PRF. This is the cm commitment

public:
    output_note_gadget(
        libsnark::protoboard<FieldT>& pb,
        std::shared_ptr<libsnark::pb_variable<FieldT>> commitment,
        const std::string &annotation_prefix = "output_note_gadget");

    void generate_r1cs_constraints();

    void generate_r1cs_witness(const ZethNote<FieldT>& note);

    // Returns the computed commitment cm
    libsnark::pb_variable<FieldT> get_cm() const;
};

} // libzeth
#include "circuits/notes/note.tcc"

#endif // __ZETH_NOTES_CIRCUITS_HPP__
