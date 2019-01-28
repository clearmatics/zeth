#ifndef __ZETH_MAIN_CIRCUIT_HPP__
#define __ZETH_MAIN_CIRCUIT_HPP__

#include <libsnark/common/data_structures/merkle_tree.hpp>

#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_authentication_path_variable.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_update_gadget.hpp>
#include <libsnark_helpers/libsnark_helpers.hpp>

#include <sha256/sha256_ethereum.hpp>
#include "computation.hpp"

#include "zeth.h" // Contains the definitions of the constants we use
#include "prover/note.tcc" // Contains the circuits for the notes

using namespace libsnark;
using namespace libff;

template<typename ppT, typename HashT, size_t NumInputs, size_t NumOutputs>
class joinsplit_gadget : gadget<libff::Fr<ppT> > {
    private:
        typedef libff::Fr<ppT> FieldT;

        // Multipacking gadgets for the inputs (root and nullifierS)
        // NumInputs + NumOutputs + 1 because we pack the nullifiers (Inputs of JS = NumInputs), 
        // the commitments (Output of JS = NumOutputs) AND the merkle root (+1) AND the v_pub taken out of the mix (+1)
        std::array<pb_variable_array<FieldT>, NumInputs + NumOutputs + 1 + 1> packed_inputs;
        std::array<pb_variable_array<FieldT>, NumInputs + NumOutputs + 1 + 1> unpacked_inputs;
        // We use an array of multipackers here instead of a single packer that packs everything
        // This leads to more public inputs (and thus affects a little bit the verification time)
        // but this makes easier to retrieve the root and each nullifiers from the public inputs
        std::array<std::shared_ptr<multipacking_gadget<FieldT>>, NumInputs + NumOutputs + 1 + 1> packers;

        // ---- Primary inputs (public)
        // NB of public inputs = 1 + NumInputs + NumOutputs + 1
        std::shared_ptr<digest_variable<FieldT> > root_digest; // merkle root
        std::array<std::shared_ptr<digest_variable<FieldT>, NumInputs> > input_nullifiers; // List of nullifiers of the notes to spend
        std::array<std::shared_ptr<digest_variable<FieldT>, NumOutputs> > output_commitments; // List of commitments generated for the new notes
        pb_variable_array<FieldT> zk_vpub; // Value that is taken out of the mix

        // ---- Auxiliary inputs (private)
        pb_variable<FieldT> ZERO;
        pb_variable_array<FieldT> zk_total_uint64;

        // Input note gadgets
        std::array<std::shared_ptr<input_note_gadget<FieldT>>, NumInputs> input_notes;

        // Output note gadgets
        std::array<std::shared_ptr<output_note_gadget<FieldT>>, NumOutputs> output_notes;

    public:
        // Make sure that we do not exceed the number of inputs/outputs
        // specified in the configuration of the JoinSplit (see: zeth.h file)
        //
        // Note1: We can relax the condition to have 2ins for 2outs for the joinsplit
        // by supporting dummy notes of value 0 
        // (this is, already supported via the constraint [value * (1 - enforce)]) in the merkle tree checks
        //
        // Note2: We should be able to easily relax the 2-2 configuration by increasing the
        // constants ZETH_NUM_JS_INPUTS and ZETH_NUM_JS_OUTPUTS in the project configuration
        assert(NumInputs <= ZETH_NUM_JS_INPUTS);
        assert(NumOutputs <= ZETH_NUM_JS_OUTPUTS);

        // ---- Primary inputs in a packed form to be added to the extended proof 
        // Given to the verifier on-chain
        //
        // WARNING: "multipacking_gadget" are not needed since we generate the primary input using
        // the function witness_map that basically packs the bit vectors into a vector of
        // field elements, while making sure it is done correctly
        //
        ////pb_variable_array<FieldT> packed_root;
        ////std::array<pb_variable_array<FieldT>, NumInputs> packed_nullifiers;

        joinsplit_gadget(protoboard<FieldT> &pb) : gadget<FieldT>(pb) {
            // Block dedicated to generate the verifier inputs
            {
                // The verification inputs are all bit-strings of various
                // lengths (256-bit digests and 64-bit integers) and so we
                // pack them into as few field elements as possible. (The
                // more verification inputs you have, the more expensive
                // verification is.)
                
                // We allocate 2 variables to pack the merkle root
                packed_inputs[0].allocate(pb, 1+1);
                for (size_t i = 1; i < NumInputs + NumOutputs + 1; i++) {
                    // Here we pack the nullifiers and the commitments
                    // Both are 256bit long and thus take 2 (1+1) field elements to be packed into
                    packed_inputs[i].allocate(pb, 1+1);
                }

                // We have one input for each input, output and for the root (they are all 256bits which takes 2field el)
                int nb_inputs = (2 * (NumInputs + NumOutputs + 1)) + 1; // There are NumInputs + NumOutputs + 1 digest inputs (each takes 2 field elements to be represented) + 1 other input whihc is the value (encoded on 64 bits so can be represented on onyl one field element)
                pb.set_input_sizes(nb_inputs);

                // Initialize the unpacked input corresponding to the root
                unpacked_inputs[0].insert(unpacked_inputs[0].end(), root_digest->bits.begin(), root_digest->bits.end());

                // Initialize the unpacked input corresponding to the inputs
                for (size_t i = 1, j = 0; i < NumInputs + 1 && j < NumInputs; i++, j++) {
                    unpacked_inputs[i].insert(
                        unpacked_inputs[i].end(), 
                        input_nullifiers[j]->bits.begin(), 
                        input_nullifiers[j]->bits.end()
                    );
                }

                // Initialize the unpacked input corresponding to the outputs
                for (size_t i = NumInputs + 1, j = 0; i < NumOutputs + NumInputs + 1 && j < NumOutputs; i++, j++) {
                    unpacked_inputs[i].insert(
                        unpacked_inputs[i].end(), 
                        output_commitments[j]->bits.begin(), 
                        output_commitments[j]->bits.end()
                    );
                }

                // Initialize the unpacked input corresponding to the v_pub (value taken out of the mix)
                unpacked_inputs[NumOutputs + NumInputs + 1].insert(
                    unpacked_inputs[NumOutputs + NumInputs + 1].end(), 
                    zk_vpub.begin(), 
                    zk_vpub-.end()
                );

                // Sanity checks with asserts
                assert(unpacked_inputs.size() == nb_inputs);
                assert(packed_inputs.size() == nb_inputs);

                // Total size of unpacked inputs
                size_t total_size_unpacked_inputs = 0;
                for(size_t i = 0; i < NumOutputs + NumInputs + 1; i++) {
                    total_size_unpacked_inputs += unpacked_inputs[i].size();
                }
                total_size_unpacked_inputs += unpacked_inputs[NumOutputs + NumInputs + 1].size() // for the v_pub

                assert(total_size_unpacked_inputs == verifying_input_bit_size());

                // These gadgets will ensure that all of the inputs we provide are
                // boolean constrained, and and correctly packed into field elements
                for(size_t i = 0; i < nb_inputs; i++) {
                    packers[i].reset(new multipacking_gadget<FieldT>(
                        pb,
                        unpacked_inputs[i],
                        zk_packed_inputs[i],
                        FieldT::capacity(),
                        "unpacker"
                    ));
                }
            }

            ZERO.allocate(pb);
            zk_total_uint64.allocate(pb, 64);

            for (size_t i = 0; i < NumInputs; i++) {
                // Input note gadget for commitments, macs, nullifiers,
                // and spend authority.
                input_notes[i].reset(new input_note_gadget<FieldT>(
                    pb,
                    ZERO,
                    input_nullifiers[i],
                    *root_digest
                ));
            }

            for (size_t i = 0; i < NumOutputs; i++) {
                output_notes[i].reset(new output_note_gadget<FieldT>(
                    pb,
                    ZERO,
                    output_commitments[i]
                ));
            }
        }

        void generate_r1cs_constraints() {
            // The true passed here ensures all the inputs
            // are boolean constrained.
            unpacker->generate_r1cs_constraints(true);

            // Constrain `ZERO`
            // Make sure that the ZERO variable is the zero of the field
            generate_r1cs_equals_const_constraint<FieldT>(this->pb, ZERO, FieldT::zero(), "ZERO");

            for (size_t i = 0; i < NumInputs; i++) {
                // Constrain the JoinSplit input constraints.
                input_notes[i]->generate_r1cs_constraints();
            }

            for (size_t i = 0; i < NumOutputs; i++) {
                // Constrain the JoinSplit output constraints.
                output_notes[i]->generate_r1cs_constraints();
            }

            // Value balance // WARNING: This is the Core of the JoinSplit.
            // Here we check that the condition of the joinsplit holds (ie: Sum_in = Sum_out)
            {
                for (size_t i = 0; i < NumInputs; i++) {
                    left_side = left_side + packed_addition(input_notes[i]->value);
                }

                // Here we only allow vpub to be used on the output side (withdraw)
                linear_combination<FieldT> right_side = packed_addition(zk_vpub);
                for (size_t i = 0; i < NumOutputs; i++) {
                    right_side = right_side + packed_addition(output_notes[i]->value);
                }

                // Ensure that both sides are equal (ie: 1 * left_side = right_side)
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
                    1,
                    left_side,
                    right_side
                ));

                // #854: Ensure that left_side is a 64-bit integer.
                for (size_t i = 0; i < 64; i++) {
                    generate_boolean_r1cs_constraint<FieldT>(
                        this->pb,
                        zk_total_uint64[i],
                        ""
                    );
                }

                // Ensure that the sum on the left has been correctly computed
                // as the sum of the inputs
                //
                // This constraint coupled with the constraint above (ie: that both sides are equal)
                // ensure that no value is created out of thin air
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
                    1,
                    left_side,
                    packed_addition(zk_total_uint64)
                ));
            }
        }

        void generate_r1cs_witness(
            const bits256& rt,
            const std::array<JSInput, NumInputs>& inputs,
            const std::array<ZethNote, NumOutputs>& outputs,
            uint64_t vpub
        ) {
            // Witness `zero`
            this->pb.val(ZERO) = FieldT::zero();

            // Witness rt. This is not a sanity check.
            //
            // This ensures the read gadget constrains
            // the intended root in the event that
            // both inputs are zero-valued.
            root_digest->bits.fill_with_bits(
                this->pb,
                get_vector_from_bits256(rt)
            );

            // Witness public balance value 
            // (vpub represents the public value that is withdrawn from the mixer)
            // v_pub is only allowed on the right side (output) in our case
            zk_vpub.fill_with_bits(
                this->pb,
                get_vector_from_bits64(vpub)
            );

            {
                // Witness total_uint64 bits
                uint64_t left_side_acc = 0; // We don't allow vpub on the left in our case
                for (size_t i = 0; i < NumInputs; i++) {
                    left_side_acc += inputs[i].note.value();
                }

                zk_total_uint64.fill_with_bits(
                    this->pb,
                    get_vector_from_bits64(left_side_acc)
                );
            }

            for (size_t i = 0; i < NumInputs; i++) {
                // Witness the input information.
                auto merkle_path = inputs[i].witness_merkle_path;
                auto merkle_path = inputs[i].address;
                auto merkle_path = inputs[i].address_bits;
                zk_input_notes[i]->generate_r1cs_witness(
                    merkle_path,
                    address,
                    address_bits,
                    inputs[i].spending_key_a_sk,
                    inputs[i].note
                );
            }

            for (size_t i = 0; i < NumOutputs; i++) {
                // Witness the output information.
                zk_output_notes[i]->generate_r1cs_witness(outputs[i]);
            }

            // [SANITY CHECK] Ensure that the intended root
            // was witnessed by the inputs, even if the read
            // gadget overwrote it. This allows the prover to
            // fail instead of the verifier, in the event that
            // the roots of the inputs do not match the
            // treestate provided to the proving API.
            root_digest->bits.fill_with_bits(
                this->pb,
                get_vector_from_bits256(rt)
            );

            // This happens last, because only by now are all the
            // verifier inputs resolved.
            unpacker->generate_r1cs_witness_from_bits();
        }

        // This function takes the inputs of the circuits, and return the r1cs_primary_inputs
        // that basically are a list of packed field elements to be added to the
        // extended proof structure that is given to the verifier contract for on-chain verification
        static r1cs_primary_input<FieldT> witness_map(
            const uint256& rt,
            const std::array<uint256, NumInputs>& nullifiers,
            const std::array<uint256, NumOutputs>& commitments,
            uint64_t vpub,
        ) {
            std::vector<bool> verify_inputs;

            insert_bits256(verify_inputs, rt);
            
            for (size_t i = 0; i < NumInputs; i++) {
                insert_bits256(verify_inputs, nullifiers[i]);
            }

            for (size_t i = 0; i < NumOutputs; i++) {
                insert_bits256(verify_inputs, commitments[i]);
            }

            insert_uint64(verify_inputs, vpub);
            
            assert(verify_inputs.size() == get_input_bit_size());
            // The pack_bit_vector_into_field_element_vector function is implemented in
            // the file: libsnark/algebra/fields/field_utils.tcc
            auto verify_field_elements = pack_bit_vector_into_field_element_vector<FieldT>(verify_inputs);
            assert(verify_field_elements.size() == get_field_element_size());
            return verify_field_elements;
        }

        // This function computes the size of the primary input
        // the inputs being binary strings here
        static size_t get_input_bit_size() {
            size_t acc = 0;

            acc += 256; // the merkle root (anchor)
            for (size_t i = 0; i < NumInputs; i++) {
                acc += 256; // nullifier
            }
            for (size_t i = 0; i < NumOutputs; i++) {
                acc += 256; // new commitment
            }
            acc += 64; // vpub

            return acc;
        }

        // This function computes the size of the primary input
        // the inputs being field elements
        static size_t verifying_field_element_size() {
            return div_ceil(get_input_bit_size(), FieldT::capacity());
        }
};


#endif