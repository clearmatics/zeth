#ifndef __ZETH_MAIN_CIRCUIT_TCC__
#define __ZETH_MAIN_CIRCUIT_TCC__

#include <libsnark/common/data_structures/merkle_tree.hpp>

#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_authentication_path_variable.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_update_gadget.hpp>
#include <libsnark_helpers/libsnark_helpers.hpp>

#include <boost/static_assert.hpp>

#include <sha256/sha256_ethereum.hpp>
#include "computation.hpp"

#include "zeth.h" // Contains the definitions of the constants we use
#include "note.tcc" // Contains the circuits for the notes

using namespace libsnark;
using namespace libff;

template<typename FieldT, typename HashT, size_t NumInputs, size_t NumOutputs>
class joinsplit_gadget : libsnark::gadget<FieldT> {
    private:
        // Multipacking gadgets for the inputs (root and nullifierS)
        // NumInputs + NumOutputs + 1 because we pack the nullifiers (Inputs of JS = NumInputs), 
        // the commitments (Output of JS = NumOutputs) AND the merkle root (+1) AND the v_pub taken out of the mix (+1)
        // AND the public value that is put into the mix (+1)
        std::array<pb_variable_array<FieldT>, NumInputs + NumOutputs + 1 + 1 + 1> packed_inputs;
        std::array<pb_variable_array<FieldT>, NumInputs + NumOutputs + 1 + 1 + 1> unpacked_inputs;
        // We use an array of multipackers here instead of a single packer that packs everything
        // This leads to more public inputs (and thus affects a little bit the verification time)
        // but this makes easier to retrieve the root and each nullifiers from the public inputs
        std::array<std::shared_ptr<multipacking_gadget<FieldT>>, NumInputs + NumOutputs + 1 + 1 + 1> packers;

        // TODO: Remove ZERO and pass it in the constructor
        pb_variable<FieldT> ZERO;

        // ---- Primary inputs (public) ----
        // NB of public inputs = 1 + NumInputs + NumOutputs + 1
        // In practice, we use sha256 as a PRF and COMM. Since the co-domain of sha256 is bigger
        // than the field we use, every digest is packed into 2 field elements. Thus the number
        // of field elements corresponding to the public inputs is:
        // Public field elements = 2 * (1 + NumInputs + NumOutputs) + 1
        std::shared_ptr<digest_variable<FieldT> > root_digest; // merkle root
        std::array<std::shared_ptr<digest_variable<FieldT> >, NumInputs> input_nullifiers; // List of nullifiers of the notes to spend
        std::array<std::shared_ptr<digest_variable<FieldT> >, NumOutputs> output_commitments; // List of commitments generated for the new notes
        pb_variable_array<FieldT> zk_vpub_in; // Public value that is put into the mix
        pb_variable_array<FieldT> zk_vpub_out; // Value that is taken out of the mix

        // ---- Auxiliary inputs (private) ----
        pb_variable_array<FieldT> zk_total_uint64;
        std::array<std::shared_ptr<input_note_gadget<FieldT>>, NumInputs> input_notes; // Input note gadgets
        std::array<std::shared_ptr<output_note_gadget<FieldT>>, NumOutputs> output_notes; // Output note gadgets
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
        BOOST_STATIC_ASSERT(NumInputs <= ZETH_NUM_JS_INPUTS);
        BOOST_STATIC_ASSERT(NumOutputs <= ZETH_NUM_JS_OUTPUTS);

        // Primary inputs are packed to be added to the extended proof and given to the verifier on-chain
        joinsplit_gadget(protoboard<FieldT> &pb,
                        const std::string &annotation_prefix = "joinsplit_gadget"
        ) : gadget<FieldT>(pb) {
            // Block dedicated to generate the verifier inputs
            std::cout << "[DEBUG] 1 in JS gadget constructor" << std::endl; 
            {
                // The verification inputs are all bit-strings of various
                // lengths (256-bit digests and 64-bit integers) and so we
                // pack them into as few field elements as possible. (The
                // more verification inputs you have, the more expensive
                // verification is.)
                
                // We allocate 2 variables to pack the merkle root
                packed_inputs[0].allocate(pb, 1 + 1);

                // We allocate 2 field elements to pack the inputs nullifiers AND the output commitments
                for (size_t i = 1; i < NumInputs + NumOutputs + 1; i++) {
                    // Here we pack the nullifiers and the commitments
                    // Both are 256bit long and thus take 2 (1+1) field elements to be packed into
                    packed_inputs[i].allocate(pb, 1 + 1);
                }

                // We allocate 1 field element to pack the value (v_pub_out)
                packed_inputs[NumInputs + NumOutputs + 1].allocate(pb, 1);

                // We allocate 1 field element to pack the value (v_pub_in)
                packed_inputs[NumInputs + NumOutputs + 1 + 1].allocate(pb, 1);

                std::cout << "[DEBUG] 1.2 in JS gadget constructor" << std::endl;

                // We have one input for each input, output and for the root (they are all 256bits which takes 2field el)
                int nb_inputs = (2 * (NumInputs + NumOutputs + 1)) + 1 + 1; // There are NumInputs + NumOutputs + 1 digest inputs (each takes 2 field elements to be represented) + 1 other input which is the value v_pub_out (encoded on 64 bits so can be represented on only one field element) + 1 input which is the v_pub_in
                pb.set_input_sizes(nb_inputs);

                std::cout << "[DEBUG] 1.3 in JS gadget constructor" << std::endl;

                // Initialize the digest_variables
                root_digest.reset(new digest_variable<FieldT>(pb, 256, FMT(this->annotation_prefix, " root_digest")));
                for (size_t i = 0; i < NumInputs; i++) {
                    input_nullifiers[i].reset(new digest_variable<FieldT>(pb, 256, FMT(this->annotation_prefix, " input_nullifiers_%zu", i)));
                }
                for (size_t i = 0; i < NumOutputs; i++) {
                    output_commitments[i].reset(new digest_variable<FieldT>(pb, 256, FMT(this->annotation_prefix, " output_commitments_%zu", i)));
                }

                // Initialize the unpacked input corresponding to the root
                unpacked_inputs[0].insert(unpacked_inputs[0].end(), root_digest->bits.begin(), root_digest->bits.end());

                std::cout << "[DEBUG] 1.4 in JS gadget constructor" << std::endl;

                // Initialize the unpacked input corresponding to the inputs
                for (size_t i = 1, j = 0; i < NumInputs + 1 && j < NumInputs; i++, j++) {
                    unpacked_inputs[i].insert(
                        unpacked_inputs[i].end(), 
                        input_nullifiers[j]->bits.begin(), 
                        input_nullifiers[j]->bits.end()
                    );
                }

                std::cout << "[DEBUG] 1.5 in JS gadget constructor" << std::endl;

                // Initialize the unpacked input corresponding to the outputs
                for (size_t i = NumInputs + 1, j = 0; i < NumOutputs + NumInputs + 1 && j < NumOutputs; i++, j++) {
                    unpacked_inputs[i].insert(
                        unpacked_inputs[i].end(), 
                        output_commitments[j]->bits.begin(), 
                        output_commitments[j]->bits.end()
                    );
                }

                std::cout << "[DEBUG] 1.6 in JS gadget constructor" << std::endl;

                // Allocate the zk_vpub_in
                zk_vpub_in.allocate(pb, 64);
                // Initialize the unpacked input corresponding to the v_pub (value taken out of the mix)
                unpacked_inputs[NumOutputs + NumInputs + 1 + 1].insert(
                    unpacked_inputs[NumOutputs + NumInputs + 1 + 1].end(), 
                    zk_vpub_in.begin(), 
                    zk_vpub_in.end()
                );

                // Allocate the zk_vpub_out
                zk_vpub_out.allocate(pb, 64);
                // Initialize the unpacked input corresponding to the v_pub (value taken out of the mix)
                unpacked_inputs[NumOutputs + NumInputs + 1].insert(
                    unpacked_inputs[NumOutputs + NumInputs + 1].end(), 
                    zk_vpub_out.begin(), 
                    zk_vpub_out.end()
                );

                std::cout << "[DEBUG] 1.7 in JS gadget constructor" << std::endl;

                // Sanity checks with asserts
                assert(unpacked_inputs.size() == nb_inputs);
                assert(packed_inputs.size() == nb_inputs);

                // Total size of unpacked inputs
                size_t total_size_unpacked_inputs = 0;
                for(size_t i = 0; i < NumOutputs + NumInputs + 1; i++) {
                    total_size_unpacked_inputs += unpacked_inputs[i].size();
                }
                total_size_unpacked_inputs += unpacked_inputs[NumOutputs + NumInputs + 1].size(); // for the v_pub

                std::cout << "[DEBUG] 1.8 in JS gadget constructor" << std::endl;

                assert(total_size_unpacked_inputs == get_input_bit_size());

                // These gadgets will ensure that all of the inputs we provide are
                // boolean constrained, and and correctly packed into field elements
                // We basically build the public inputs here
                // First we pack the root
                packers[0].reset(new multipacking_gadget<FieldT>(
                    pb,
                    unpacked_inputs[0],
                    packed_inputs[0],
                    FieldT::capacity(),
                    FMT(this->annotation_prefix, " packer_root")
                ));

                // Then we pack the nullifiers
                for (size_t i = 1; i < NumInputs + 1 ; i++) {
                    packers[i].reset(new multipacking_gadget<FieldT>(
                        pb,
                        unpacked_inputs[i],
                        packed_inputs[i],
                        FieldT::capacity(),
                        FMT(this->annotation_prefix, " packer_nullifiers_%zu", i)
                    ));
                }

                // Finally we pack the output commitments
                for (size_t i = NumInputs + 1; i < NumOutputs + NumInputs + 1; i++) {
                    packers[i].reset(new multipacking_gadget<FieldT>(
                        pb,
                        unpacked_inputs[i],
                        packed_inputs[i],
                        FieldT::capacity(),
                        FMT(this->annotation_prefix, " packer_output_commitments_%zu", i)
                    ));
                }

                packers[NumInputs + NumOutputs + 1].reset(new multipacking_gadget<FieldT>(
                    pb,
                    unpacked_inputs[NumInputs + NumOutputs + 1],
                    packed_inputs[NumInputs + NumOutputs + 1],
                    FieldT::capacity(),
                    FMT(this->annotation_prefix, " packer_value_pub_out")
                ));

                packers[NumInputs + NumOutputs + 1 + 1].reset(new multipacking_gadget<FieldT>(
                    pb,
                    unpacked_inputs[NumInputs + NumOutputs + 1 + 1],
                    packed_inputs[NumInputs + NumOutputs + 1 + 1],
                    FieldT::capacity(),
                    FMT(this->annotation_prefix, " packer_value_pub_in")
                ));
            }
            std::cout << "[DEBUG] 2 in JS gadget constructor" << std::endl; 

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

            std::cout << " ================= [DEBUG] 1 in JS generate_r1cs_constraints" << std::endl; 

            /*
            for (size_t i = 0; i < NumInputs; i++) {
                input_nullifiers[i]->generate_r1cs_constraints();
            }
            for (size_t i = 0; i < NumOutputs; i++) {
                output_commitments[i]->generate_r1cs_constraints();
            }
            
            root_digest->generate_r1cs_constraints();
            */

            // The true passed here ensures all the inputs
            // are boolean constrained.
            for(size_t i = 0; i < packers.size(); i++) {
                packers[i]->generate_r1cs_constraints(true);
            }

            std::cout << " ================= [DEBUG] 2 in JS generate_r1cs_constraints" << std::endl; 

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

            std::cout << " ================= [DEBUG] 3 in JS generate_r1cs_constraints" << std::endl; 

            // Value balance // WARNING: This is the Core of the JoinSplit.
            // Here we check that the condition of the joinsplit holds (ie: Sum_in = Sum_out)
            {
                linear_combination<FieldT> left_side = packed_addition(zk_vpub_in);
                for (size_t i = 0; i < NumInputs; i++) {
                    left_side = left_side + packed_addition(input_notes[i]->value);
                }

                std::cout << " ================= [DEBUG] 4 in JS generate_r1cs_constraints" << std::endl;
                std::cout << "[DEBUG] 4.1 in JS generate_r1cs_constraints" << std::endl; 
                std::cout << "[DEBUG] 4.2 in JS generate_r1cs_constraints" << std::endl; 

                // Here we only allow vpub_out to be used on the output side (withdraw)
                linear_combination<FieldT> right_side = packed_addition(zk_vpub_out);
                for (size_t i = 0; i < NumOutputs; i++) {
                    right_side = right_side + packed_addition(output_notes[i]->value);
                }

                std::cout << " ================= [DEBUG] 5 in JS generate_r1cs_constraints" << std::endl; 

                // Ensure that both sides are equal (ie: 1 * left_side = right_side)
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
                    1,
                    left_side,
                    right_side
                ));

                std::cout << " ================= [DEBUG] 6 in JS generate_r1cs_constraints" << std::endl; 

                // #854: Ensure that left_side is a 64-bit integer.
                for (size_t i = 0; i < 64; i++) {
                    generate_boolean_r1cs_constraint<FieldT>(
                        this->pb,
                        zk_total_uint64[i],
                        FMT(this->annotation_prefix, " boolean_constraint_zk_total_uint64_%zu", i)
                    );
                }

                std::cout << " ================= [DEBUG] 7 in JS generate_r1cs_constraints" << std::endl; 

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
            bits64 vpub_in,
            bits64 vpub_out
        ) {
            std::cout << "\n [[[[[[[[[[[[[[DEBUG] -1- in JS generate_r1cs_constraints ]]]]]]]]]]]]]]]\n" << std::endl; 
            // Witness `zero`
            this->pb.val(ZERO) = FieldT::zero();

            /*
            for (size_t i = 0; i < NumInputs; i++) {
                input_nullifiers[i]->generate_r1cs_witness(libff::bit_vector(get_vector_from_bits256(inputs[i].nullifier)));
            }
            for (size_t i = 0; i < NumOutputs; i++) {
                output_commitments[i]->generate_r1cs_witness(libff::bit_vector(get_vector_from_bits256(outputs[i].cm)));
            }
            */
            root_digest->generate_r1cs_witness(libff::bit_vector(get_vector_from_bits256(rt)));

            // Witness rt. This is not a sanity check.
            //
            // This ensures the read gadget constrains
            // the intended root in the event that
            // both inputs are zero-valued.
            //root_digest->bits.fill_with_bits(
            //    this->pb,
            //    get_vector_from_bits256(rt)
            //);
            std::cout << "\n [[[[[[[[[[[[[[DEBUG] -2- in JS generate_r1cs_constraints ]]]]]]]]]]]]]]]\n" << std::endl;

            // Witness public balance value 
            // (vpub_out represents the public value that is withdrawn from the mixer)
            // v_pub is only allowed on the right side (output) in our case
            zk_vpub_out.fill_with_bits(
                this->pb,
                get_vector_from_bits64(vpub_out)
            );

            zk_vpub_in.fill_with_bits(
                this->pb,
                get_vector_from_bits64(vpub_in)
            );

            // /!\ We witness the multipacking gadgets before we overwrite any data.
            // This constitutes the public inputs
            //
            // Note that when we witness the gadgets below we migth overwrite some data
            // This is fine here because, the proof should pass if all the data structures' content
            // are overwritten with the same data.
            // HOWEVER, if the prover uses erroneous/malicious data as assignement to the circuit,
            // then the witnessed data packed into the packing gagdets will differ from the same data
            // structures' content used in the proof generation, and thus the proof will fail to be verified
            // by the on-chain verifier
            ////for(size_t i = 0; i < packers.size(); i++) {
            ////    packers[i]->generate_r1cs_witness_from_bits();
            ////}

            std::cout << "\n [[[[[[[[[[[[[[DEBUG] -3- in JS generate_r1cs_constraints ]]]]]]]]]]]]]]]\n" << std::endl;

            {
                // Witness total_uint64 bits
                // We add binary numbers here
                // see: https://stackoverflow.com/questions/13282825/adding-binary-numbers-in-c
                ///std::array<bool, 64> zero_array;
                ///zero_array.fill(0);
                ///bits64 left_side_acc = zero_array; // We don't allow vpub_out on the left in our case (TODO: allow it)
                bits64 left_side_acc = vpub_in;
                for (size_t i = 0; i < NumInputs; i++) {
                    left_side_acc = binaryAddition<64>(left_side_acc, inputs[i].note.value());
                }

                zk_total_uint64.fill_with_bits(
                    this->pb,
                    get_vector_from_bits64(left_side_acc)
                );
            }

            std::cout << "\n [[[[[[[[[[[[[[DEBUG] -4- in JS generate_r1cs_constraints ]]]]]]]]]]]]]]]\n" << std::endl;

            for (size_t i = 0; i < NumInputs; i++) {
                // Witness the input information.
                std::vector<libsnark::merkle_authentication_node> merkle_path = inputs[i].witness_merkle_path;
                size_t address = inputs[i].address;
                libff::bit_vector address_bits = get_vector_from_bitsAddr(inputs[i].address_bits);
                input_notes[i]->generate_r1cs_witness(
                    merkle_path,
                    address,
                    address_bits,
                    inputs[i].spending_key_a_sk,
                    inputs[i].note
                );
            }

            std::cout << "\n [[[[[[[[[[[[[[DEBUG] -5- in JS generate_r1cs_constraints ]]]]]]]]]]]]]]]\n" << std::endl;

            /*
                    std::vector<libsnark::merkle_authentication_node> merkle_path,
                    size_t address,
                    libff::bit_vector address_bits,
                    const bits256 a_sk_in,
                    const ZethNote& note
            */

            for (size_t i = 0; i < NumOutputs; i++) {
                // Witness the output information.
                std::cout << "Displaying the output_note details: " << std::endl;
                std::cout << "value size: " << outputs[i].value().size() << std::endl;
                auto val = outputs[i].value();
                std::cout << "value: ";
                for(int i = 0; i < val.size(); i++) {
                    std::cout << val[i];
                }
                /*
                std::cout << std::endl;
                std::cout << "commitment given: " << outputs[i].cm.size() << std::endl;
                auto val_cm = outputs[i].cm;
                for(int i = 0; i < val_cm.size(); i++) {
                    std::cout << val_cm[i];
                } 
                std::cout << std::endl;
                */
                output_notes[i]->generate_r1cs_witness(outputs[i]);
            }

            std::cout << "\n [[[[[[[[[[[[[[DEBUG] -6- in JS generate_r1cs_constraints ]]]]]]]]]]]]]]]\n" << std::endl;
            //
            // [SANITY CHECK] Ensure that the intended root
            //    // was witnessed by the inputs, even if the read
            //    // gadget overwrote it. This allows the prover to 
            //   // fail instead of the verifier, in the event that
            //    // the roots of the inputs do not match the
            //    // treestate provided to the proving API.
            root_digest->bits.fill_with_bits(
                this->pb,
                get_vector_from_bits256(rt)
            );
            //
            std::cout << "\n [[[[[[[[[[[[[[DEBUG] -6- in JS generate_r1cs_constraints ]]]]]]]]]]]]]]]\n" << std::endl;
            //
            //    // This happens last, because only by now are all the
            //    // verifier inputs resolved.
            for(size_t i = 0; i < packers.size(); i++) {
                packers[i]->generate_r1cs_witness_from_bits();
            }
        }

        // This function takes the inputs of the circuits, and return the r1cs_primary_inputs
        // that basically are a list of packed field elements to be added to the
        // extended proof structure that is given to the verifier contract for on-chain verification
        /*
        static r1cs_primary_input<FieldT> witness_map(
            const bits256& rt,
            const std::array<bits256, NumInputs>& nullifiers,
            const std::array<bits256, NumOutputs>& commitments,
            bits64 vpub_out,
        ) {
            std::vector<bool> verify_inputs;

            insert_bits256(verify_inputs, rt);
            
            for (size_t i = 0; i < NumInputs; i++) {
                insert_bits256(verify_inputs, nullifiers[i]);
            }

            for (size_t i = 0; i < NumOutputs; i++) {
                insert_bits256(verify_inputs, commitments[i]);
            }

            insert_uint64(verify_inputs, vpub_out);
            
            assert(verify_inputs.size() == get_input_bit_size());
            // The pack_bit_vector_into_field_element_vector function is implemented in
            // the file: libsnark/algebra/fields/field_utils.tcc
            auto verify_field_elements = pack_bit_vector_into_field_element_vector<FieldT>(verify_inputs);
            assert(verify_field_elements.size() == get_field_element_size());
            return verify_field_elements;
        }
        */

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
            acc += 64; // vpub_out
            acc += 64; // vpub_in

            return acc;
        }

        // This function computes the size of the primary input
        // the inputs being field elements
        static size_t verifying_field_element_size() {
            return div_ceil(get_input_bit_size(), FieldT::capacity());
        }
};

#endif // __ZETH_MAIN_CIRCUIT_TCC__