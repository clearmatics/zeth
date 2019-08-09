#ifndef __ZETH_JOINSPLIT_CIRCUIT_TCC__
#define __ZETH_JOINSPLIT_CIRCUIT_TCC__

#include <src/types/merkle_tree_field.hpp>

#include <boost/static_assert.hpp>

#include "libsnark_helpers/libsnark_helpers.hpp"
#include "circuits/sha256/sha256_ethereum.hpp"
#include "circuits/notes/note.hpp" // Contains the circuits for the notes

#include "types/joinsplit.hpp"

#include "zeth.h" // Contains the definitions of the constants we use

using namespace libsnark;
using namespace libff;
using namespace libzeth;

template<typename FieldT, typename HashT, typename HashTreeT, size_t NumInputs, size_t NumOutputs>
class joinsplit_gadget : libsnark::gadget<FieldT> {
    private:
        /*
         * Multipacking gadgets for the inputs (nullifierS, commitmentS, val_pub_in, val_pub_out) (the root is a field element)
         * `NumInputs + NumOutputs` because we pack the nullifiers (Inputs of JS = NumInputs), the commitments (Output of JS = NumOutputs)
         * AND the v_pub_out taken out of the mix (+1) AND the public value v_pub_in that is put into the mix (+1)
        **/
        std::array<pb_variable_array<FieldT>, NumInputs + NumOutputs + 1 + 1> packed_inputs;
        std::array<pb_variable_array<FieldT>, NumInputs + NumOutputs + 1 + 1> unpacked_inputs;

        /* We use an array of multipackers here instead of a single packer that packs everything.
         * This leads to more public inputs (and thus affects a little bit the verification time)
         * but this makes easier to retrieve the root and each nullifiers from the public inputs
        **/
        std::array<std::shared_ptr<multipacking_gadget<FieldT>>, NumInputs + NumOutputs + 1 + 1 > packers;

        // TODO: Remove ZERO and pass it in the constructor
        pb_variable<FieldT> ZERO;

        // ---- Primary inputs (public) ---- //
        std::shared_ptr<pb_variable<FieldT> > merkle_root; // Merkle root
        std::array<std::shared_ptr<digest_variable<FieldT> >, NumInputs> input_nullifiers; // List of nullifiers of the notes to spend
        std::array<std::shared_ptr<digest_variable<FieldT> >, NumOutputs> output_commitments; // List of commitments generated for the new notes
        pb_variable_array<FieldT> zk_vpub_in; // Public value that is put into the mix
        pb_variable_array<FieldT> zk_vpub_out; // Value that is taken out of the mix

        // ---- Auxiliary inputs (private) ---- //
        pb_variable_array<FieldT> zk_total_uint64; // Total amount transfered in the transaction
        std::array<std::shared_ptr<input_note_gadget<FieldT, HashT, HashTreeT>>, NumInputs> input_notes; // Input note gadgets
        std::array<std::shared_ptr<output_note_gadget<FieldT, HashT>>, NumOutputs> output_notes; // Output note gadgets
    public:
        // Make sure that we do not exceed the number of inputs/outputs
        // specified in zeth's configuration file (see: zeth.h file)
        BOOST_STATIC_ASSERT(NumInputs <= ZETH_NUM_JS_INPUTS);
        BOOST_STATIC_ASSERT(NumOutputs <= ZETH_NUM_JS_OUTPUTS);

        // Primary inputs are packed to be added to the extended proof and given to the verifier on-chain
        joinsplit_gadget(protoboard<FieldT> &pb,
                         const std::string &annotation_prefix = "joinsplit_gadget"
        ) : gadget<FieldT>(pb, annotation_prefix) {
            // Block dedicated to generate the verifier inputs
            {
                // The verification inputs are, except for the root, all bit-strings of various
                // lengths (256-bit digests and 64-bit integers) and so we
                // pack them into as few field elements as possible. (The
                // more verification inputs you have, the more expensive
                // verification is.)

                // ------------------------- ALLOCATION OF PRIMARY INPUTS ------------------------- //
                /*
                 * We make sure to have the primary inputs ordered as follow:
                 * [Root, NullifierS, CommitmentS, value_pub_in, value_pub_out]
                 * ie, below is the index mapping of the primary input elements on the protoboard:
                 * - Index of the "Root" field elements: {0}
                 * - Index of the "NullifierS" field elements: [1, NumInputs + 1[
                 * - Index of the "CommitmentS" field elements: [NumInputs + 1, NumOutputs + NumInputs + 1[
                 * - Index of the "v_pub_in" field element: {NumOutputs + NumInputs + 1}
                 * - Index of the "v_pub_out" field element: {NumOutputs + NumInputs + 1 + 1}
                **/
                // We first allocate the root
                merkle_root.reset(new libsnark::pb_variable<FieldT>);
                merkle_root->allocate(pb, FMT(this->annotation_prefix, " merkle_root"));

                // We allocate 2 field elements to pack each inputs nullifiers and each output commitments
                for (size_t i = 0; i < NumInputs + NumOutputs; i++) {
                    packed_inputs[i].allocate(pb, 1 + 1);
                }

                // We allocate 1 field element to pack the value (v_pub_in)
                packed_inputs[NumInputs + NumOutputs].allocate(pb, 1, " v_pub_in");

                // We allocate 1 field element to pack the value (v_pub_out)
                packed_inputs[NumInputs + NumOutputs + 1].allocate(pb, 1, " v_pub_out");

                // The inputs are: [Root, NullifierS, CommitmentS, value_pub_in, value_pub_out]
                // The root is represented on a single field element
                // Each nullifier, and each commitment are in {0,1}^256 and thus take 2 field elements to be represented,
                // while value_pub_in, and value_pub_out are in {0,1}^64, and thus take a single field element to be represented
                int nb_inputs = 1 + (2 * (NumInputs + NumOutputs)) + 1 + 1;
                pb.set_input_sizes(nb_inputs);
                // ------------------------------------------------------------------------------ //

                // Initialize the digest_variables
                for (size_t i = 0; i < NumInputs; i++) {
                    input_nullifiers[i].reset(new digest_variable<FieldT>(pb, HashT::get_digest_len(), FMT(this->annotation_prefix, " input_nullifiers_%zu", i)));
                }
                for (size_t i = 0; i < NumOutputs; i++) {
                    output_commitments[i].reset(new digest_variable<FieldT>(pb, HashT::get_digest_len(), FMT(this->annotation_prefix, " output_commitments_%zu", i)));
                }

                // Initialize the unpacked input corresponding to the input NullifierS
                for (size_t i = 0; i < NumInputs; i++) {
                    unpacked_inputs[i].insert(
                        unpacked_inputs[i].end(),
                        input_nullifiers[i]->bits.begin(),
                        input_nullifiers[i]->bits.end()
                    );
                }

                // Initialize the unpacked input corresponding to the output CommitmentS
                for (size_t i = NumInputs , j = 0; i < NumOutputs + NumInputs  && j < NumOutputs; i++, j++) {
                    unpacked_inputs[i].insert(
                        unpacked_inputs[i].end(),
                        output_commitments[j]->bits.begin(),
                        output_commitments[j]->bits.end()
                    );
                }

                // Allocate the zk_vpub_in
                zk_vpub_in.allocate(pb, 64, " zk_vpub_in");
                // Initialize the unpacked input corresponding to the vpub_in (public value added to the mix)
                unpacked_inputs[NumOutputs + NumInputs ].insert(
                    unpacked_inputs[NumOutputs + NumInputs ].end(),
                    zk_vpub_in.begin(),
                    zk_vpub_in.end()
                );

                // Allocate the zk_vpub_out
                zk_vpub_out.allocate(pb, 64, " zk_vpub_out");
                // Initialize the unpacked input corresponding to the vpub_out (public value taken out of the mix)
                unpacked_inputs[NumOutputs + NumInputs + 1 ].insert(
                    unpacked_inputs[NumOutputs + NumInputs + 1].end(),
                    zk_vpub_out.begin(),
                    zk_vpub_out.end()
                );

                // [SANITY CHECK]
                // The root is a FieldT, hence is not packed
                // The size of the packed inputs should be
                // NumInputs + NumOutputs + 1 + 1 since we are packing all the inputs nullifiers
                // + all the output commitments + the two public values v_pub_in and v_pub_out
                assert(packed_inputs.size() == NumInputs + NumOutputs + 1 + 1);
                assert(nb_inputs == [&packed_inputs]() {
                    size_t sum = 0;
                    for (const auto &i : packed_inputs) { sum = sum + i.size(); }
                    return sum;
                });

                // [SANITY CHECK] Total size of unpacked inputs
                size_t total_size_unpacked_inputs = 0;
                for(size_t i = 0; i < NumOutputs + NumInputs ; i++) {
                    total_size_unpacked_inputs += unpacked_inputs[i].size();
                }
                total_size_unpacked_inputs += unpacked_inputs[NumOutputs + NumInputs ].size(); // for the v_pub_in
                total_size_unpacked_inputs += unpacked_inputs[NumOutputs + NumInputs + 1].size(); // for the v_pub_out
                assert(total_size_unpacked_inputs == get_input_bit_size());

                // These gadgets will ensure that all of the inputs we provide are
                // boolean constrained, and and correctly packed into field elements
                // We basically build the public inputs here
                //
                // 1. Pack the nullifiers
                for (size_t i = 0; i < NumInputs  ; i++) {
                    packers[i].reset(new multipacking_gadget<FieldT>(
                        pb,
                        unpacked_inputs[i],
                        packed_inputs[i],
                        FieldT::capacity(),
                        FMT(this->annotation_prefix, " packer_nullifiers_%zu", i)
                    ));
                }

                // 2. Pack the output commitments
                for (size_t i = NumInputs ; i < NumOutputs + NumInputs ; i++) {
                    packers[i].reset(new multipacking_gadget<FieldT>(
                        pb,
                        unpacked_inputs[i],
                        packed_inputs[i],
                        FieldT::capacity(),
                        FMT(this->annotation_prefix, " packer_output_commitments_%zu", i)
                    ));
                }

                // 3. Pack the vpub_in
                packers[NumInputs + NumOutputs ].reset(new multipacking_gadget<FieldT>(
                    pb,
                    unpacked_inputs[NumInputs + NumOutputs ],
                    packed_inputs[NumInputs + NumOutputs ],
                    FieldT::capacity(),
                    FMT(this->annotation_prefix, " packer_value_pub_in")
                ));

                // 4. Pack the vpub_out
                packers[NumInputs + NumOutputs + 1].reset(new multipacking_gadget<FieldT>(
                    pb,
                    unpacked_inputs[NumInputs + NumOutputs + 1 ],
                    packed_inputs[NumInputs + NumOutputs + 1 ],
                    FieldT::capacity(),
                    FMT(this->annotation_prefix, " packer_value_pub_out")
                ));
            } // End of the block dedicated to generate the verifier inputs

            ZERO.allocate(pb, " zero");
            zk_total_uint64.allocate(pb, 64, " zk_total");

            // Input note gadgets for commitments, nullifiers, and spend authority
            for (size_t i = 0; i < NumInputs; i++) {
                input_notes[i].reset(new input_note_gadget<FieldT, HashT, HashTreeT>(
                    pb,
                    ZERO,
                    input_nullifiers[i],
                    *merkle_root
                ));
            }

            for (size_t i = 0; i < NumOutputs; i++) {
                output_notes[i].reset(new output_note_gadget<FieldT, HashT>(
                    pb,
                    ZERO,
                    output_commitments[i]
                ));
            }
        }

        void generate_r1cs_constraints() {
            // The `true` passed to `generate_r1cs_constraints` ensures that all inputs are boolean strings
            for(size_t i = 0; i < packers.size(); i++) {
                packers[i]->generate_r1cs_constraints(true);
            }

            // Constrain `ZERO`: Make sure that the ZERO variable is the zero of the field
            generate_r1cs_equals_const_constraint<FieldT>(this->pb, ZERO, FieldT::zero(), "ZERO");

            // Constrain the JoinSplit inputs
            for (size_t i = 0; i < NumInputs; i++) {
                input_notes[i]->generate_r1cs_constraints();
            }

            // Constrain the JoinSplit outputs
            for (size_t i = 0; i < NumOutputs; i++) {
                output_notes[i]->generate_r1cs_constraints();
            }

            // Generate the constraints to ensure that the condition of the joinsplit holds (ie: LHS = RHS)
            {
                // Compute the LHS
                linear_combination<FieldT> left_side = packed_addition(zk_vpub_in);
                for (size_t i = 0; i < NumInputs; i++) {
                    left_side = left_side + packed_addition(input_notes[i]->value);
                }

                // Compute the RHS
                linear_combination<FieldT> right_side = packed_addition(zk_vpub_out);
                for (size_t i = 0; i < NumOutputs; i++) {
                    right_side = right_side + packed_addition(output_notes[i]->value);
                }

                // Ensure that both sides are equal (ie: 1 * left_side = right_side)
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
                        1,
                        left_side,
                        right_side
                    ),
                    FMT(this->annotation_prefix, " lhs_rhs_equality_constraint")
                );

                // See: https://github.com/zcash/zcash/issues/854
                // Ensure that `left_side` is a 64-bit integer
                for (size_t i = 0; i < 64; i++) {
                    generate_boolean_r1cs_constraint<FieldT>(
                        this->pb,
                        zk_total_uint64[i],
                        FMT(this->annotation_prefix, " boolean_constraint_zk_total_uint64_%zu", i)
                    );
                }

                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
                        1,
                        left_side,
                        packed_addition(zk_total_uint64)
                    ),
                    FMT(this->annotation_prefix, " lhs_equal_zk_total_constraint")
                );
            }
        }

        void generate_r1cs_witness(
            const FieldT& rt,
            const std::array<JSInput<FieldT>, NumInputs>& inputs,
            const std::array<ZethNote, NumOutputs>& outputs,
            bits64 vpub_in,
            bits64 vpub_out
        ) {
            // Witness `zero`
            this->pb.val(ZERO) = FieldT::zero();

            // Witness the merkle root
            this->pb.val(*merkle_root) = rt;

            // Witness public values
            //
            // Witness LHS public value
            zk_vpub_in.fill_with_bits(
                this->pb,
                get_vector_from_bits64(vpub_in)
            );

            // Witness RHS public value
            zk_vpub_out.fill_with_bits(
                this->pb,
                get_vector_from_bits64(vpub_out)
            );

            {
                // Witness total_uint64 bits
                // We add binary numbers here
                // see: https://stackoverflow.com/questions/13282825/adding-binary-numbers-in-c
                bits64 left_side_acc = vpub_in;
                for (size_t i = 0; i < NumInputs; i++) {
                    left_side_acc = binaryAddition<64>(left_side_acc, inputs[i].note.value());
                }

                zk_total_uint64.fill_with_bits(
                    this->pb,
                    get_vector_from_bits64(left_side_acc)
                );
            }

            // Witness the JoinSplit inputs
            for (size_t i = 0; i < NumInputs; i++) {
                std::vector<FieldT> merkle_path = inputs[i].witness_merkle_path;
                libff::bit_vector address_bits = get_vector_from_bitsAddr(inputs[i].address_bits);
                input_notes[i]->generate_r1cs_witness(
                    merkle_path,
                    address_bits,
                    inputs[i].spending_key_a_sk,
                    inputs[i].note
                );
            }

            // Witness the JoinSplit outputs
            for (size_t i = 0; i < NumOutputs; i++) {
                output_notes[i]->generate_r1cs_witness(outputs[i]);
            }

            // This happens last, because only by now are all the
            // verifier inputs resolved.
            for(size_t i = 0; i < packers.size(); i++) {
                packers[i]->generate_r1cs_witness_from_bits();
            }

        }

        // Computes the binary size of the primary inputs
        static size_t get_input_bit_size() {
            size_t acc = 0;

            // Binary length of the Merkle Root (anchor)
            acc += 256;

            // Binary length of the NullifierS
            for (size_t i = 0; i < NumInputs; i++) {
                acc += 256;
            }

            // Binary length of the CommitmentS
            for (size_t i = 0; i < NumOutputs; i++) {
                acc += 256;
            }

            // Binary length of vpub_in
            acc += 64;

            // Binary length of vpub_out
            acc += 64;

            return acc;
        }

        // Computes the number of field elements in the primary inputs
        static size_t verifying_field_element_size() {
            return div_ceil(get_input_bit_size(), FieldT::capacity());
        }
};

#endif // __ZETH_JOINSPLIT_CIRCUIT_TCC__
