#ifndef __ZETH_CIRCUITS_JOINSPLIT_TCC__
#define __ZETH_CIRCUITS_JOINSPLIT_TCC__

// Contains the circuits for the notes
#include "circuits/notes/note.hpp"
#include "libsnark_helpers/libsnark_helpers.hpp"
#include "types/joinsplit.hpp"
// Contains the definitions of the constants we use
#include "zeth.h"

#include <boost/static_assert.hpp>
#include <src/types/merkle_tree_field.hpp>

using namespace libzeth;

template<
    typename FieldT,
    typename HashT,
    typename HashTreeT,
    size_t NumInputs,
    size_t NumOutputs>
class joinsplit_gadget : libsnark::gadget<FieldT>
{
private:
    // Number of residual bits from packing of 256-bit long string into 253-bit
    // long field elements to which are added the public value of size 64 bits
    const size_t length_bit_residual =
        2 * 64 + (HashT::get_digest_len() - FieldT::capacity()) *
                     (1 + 2 * NumInputs + NumOutputs);
    // Number of field elements needed to pack this number of bits
    const size_t nb_field_residual =
        libff::div_ceil(length_bit_residual, FieldT::capacity());

    // Multipacking gadgets for the inputs (nullifierS, commitmentS, hsig,
    // malleability tags and the residual bits (comprising the previous
    // variables' bits not containable in a single field element as well as the
    // public values) (the root is a field element) because we pack the
    // nullifiers (Inputs of JS = NumInputs), the commitments (Output of JS =
    // NumOutputs) AND the signature hash h_sig (+1) AND the malleability tags
    // h_iS (+ NumInputs) AND aggregate the extra bits and public values (+1)

    std::array<
        libsnark::pb_variable_array<FieldT>,
        NumInputs + NumOutputs + 1 + NumInputs + 1>
        packed_inputs;
    std::array<
        libsnark::pb_variable_array<FieldT>,
        NumInputs + NumOutputs + 1 + NumInputs + 1>
        unpacked_inputs;

    // We use an array of multipackers here instead of a single packer that
    // packs everything. This leads to more public inputs (and thus affects a
    // little bit the verification time) but this makes easier to retrieve the
    // root and each nullifiers from the public inputs
    std::array<
        std::shared_ptr<libsnark::multipacking_gadget<FieldT>>,
        NumInputs + NumOutputs + 1 + NumInputs + 1>
        packers;

    libsnark::pb_variable<FieldT> ZERO;

    // ---- Primary inputs (public) ---- //
    // Merkle Root
    std::shared_ptr<libsnark::pb_variable<FieldT>> merkle_root;
    // List of nullifiers of the notes to spend
    std::array<std::shared_ptr<libsnark::digest_variable<FieldT>>, NumInputs>
        input_nullifiers;
    // List of commitments generated for the new notes
    std::array<std::shared_ptr<libsnark::digest_variable<FieldT>>, NumOutputs>
        output_commitments;
    // Public value that is put into the mix
    libsnark::pb_variable_array<FieldT> zk_vpub_in;
    // Value that is taken out of the mix
    libsnark::pb_variable_array<FieldT> zk_vpub_out;
    // sighash h Sig := hSigCRH(randomSeed, {nf_old}, joinSplitPubKey) (p.53
    // ZCash proto. spec.)
    std::shared_ptr<libsnark::digest_variable<FieldT>> h_sig;
    // List of message authentication tags
    std::array<std::shared_ptr<libsnark::digest_variable<FieldT>>, NumInputs>
        h_is;

    // ---- Auxiliary inputs (private) ---- //
    // Total amount transfered in the transaction
    libsnark::pb_variable_array<FieldT> zk_total_uint64;
    // List of all spending keys
    std::array<std::shared_ptr<libsnark::digest_variable<FieldT>>, NumInputs>
        a_sks;
    // List of all output rhos
    std::array<std::shared_ptr<libsnark::digest_variable<FieldT>>, NumOutputs>
        rho_is;
    // random seed for uniqueness of the new rho
    std::shared_ptr<libsnark::digest_variable<FieldT>> phi;

    // Input note gadgets
    std::array<
        std::shared_ptr<input_note_gadget<FieldT, HashT, HashTreeT>>,
        NumInputs>
        input_notes;
    std::array<std::shared_ptr<PRF_pk_gadget<FieldT, HashT>>, NumInputs>
        h_i_gadgets;

    // Output note gadgets
    std::array<std::shared_ptr<PRF_rho_gadget<FieldT, HashT>>, NumOutputs>
        rho_i_gadgets;
    std::array<std::shared_ptr<output_note_gadget<FieldT, HashT>>, NumOutputs>
        output_notes;

public:
    // Make sure that we do not exceed the number of inputs/outputs
    // specified in zeth's configuration file (see: zeth.h file)
    BOOST_STATIC_ASSERT(NumInputs <= ZETH_NUM_JS_INPUTS);
    BOOST_STATIC_ASSERT(NumOutputs <= ZETH_NUM_JS_OUTPUTS);

    // Primary inputs are packed to be added to the extended proof and given to
    // the verifier on-chain
    joinsplit_gadget(
        libsnark::protoboard<FieldT> &pb,
        const std::string &annotation_prefix = "joinsplit_gadget")
        : libsnark::gadget<FieldT>(pb, annotation_prefix)
    {
        // Block dedicated to generate the verifier inputs
        {
            // The verification inputs are, except for the root, all bit-strings
            // of various lengths (256-bit digests and 64-bit integers) and so
            // we pack them into as few field elements as possible. (The more
            // verification inputs you have, the more expensive verification
            // is.)

            // --------- ALLOCATION OF PRIMARY INPUTS -------- //
            // We make sure to have the primary inputs ordered as follow:
            // [Root, NullifierS, CommitmentS, value_pub_in, value_pub_out]
            // ie, below is the index mapping of the primary input elements on
            // the protoboard:
            // - Index of the "Root" field element: {0}
            // - Index of the "NullifierS" field elements: [1, NumInputs + 1[
            // - Index of the "CommitmentS" field elements: [NumInputs + 1,
            //   NumOutputs + NumInputs + 1[
            // - Index of the "h_sig" field element: {NumOutputs + NumInputs + 1
            //   }
            // - Index of the "h_iS" field elements: [NumOutputs + NumInputs + 1
            //   + 1,  NumOutputs + NumInputs + 1 + NumInputs[
            // - Index of the "v_pub_in", "v_pub_out", and bits of previous
            //   variables not fitting within FieldT::capacity() [NumOutputs +
            //   NumInputs + 1 + NumInputs, NumOutputs + NumInputs + 1 +
            //   NumInputs + nb_field_residual[

            // We first allocate the root
            merkle_root.reset(new libsnark::pb_variable<FieldT>);
            merkle_root->allocate(
                pb, FMT(this->annotation_prefix, " merkle_root"));

            // We allocate a field element for each of the input nullifiers and
            // output commitments to pack their first FieldT::capacity() bits
            for (size_t i = 0; i < NumInputs; i++) {
                packed_inputs[i].allocate(
                    pb,
                    1,
                    FMT(this->annotation_prefix, " in_nullifier[%zu]", i));
            }
            for (size_t i = NumInputs; i < NumInputs + NumOutputs; i++) {
                packed_inputs[i].allocate(
                    pb,
                    1,
                    FMT(this->annotation_prefix, " out_commitment[%zu]", i));
            }

            // We allocate a field element FOR h_sig to pack its first
            // FieldT::capacity() bits
            packed_inputs[NumInputs + NumOutputs].allocate(
                pb, 1, FMT(this->annotation_prefix, " h_sig"));

            // We allocate a field element for each message authentication tags
            // h_iS to pack their first FieldT::capacity() bits
            for (size_t i = NumInputs + NumOutputs + 1;
                 i < NumInputs + NumOutputs + 1 + NumInputs;
                 i++) {
                packed_inputs[i].allocate(
                    pb, 1, FMT(this->annotation_prefix, " h_i[%zu]", i));
            }

            // We allocate as many field elements as needed to pack the public
            // values and the hash digests' residual bits
            packed_inputs[NumInputs + NumOutputs + 1 + NumInputs].allocate(
                pb, nb_field_residual, FMT(this->annotation_prefix, " bits"));

            // The primary inputs are: [Root, NullifierS, CommitmentS,
            // value_pub_in, value_pub_out, h_sig, h_iS] The root is represented
            // on a single field element H_sig, as well as each nullifier,
            // commitment and h_i are in {0,1}^256 and thus take 2 field
            // elements to be represented, while value_pub_in, and value_pub_out
            // are in {0,1}^64, and thus take a single field element to be
            // represented
            const size_t nb_packed_inputs =
                2 * NumInputs + NumOutputs + 1 + nb_field_residual;
            const size_t nb_inputs = 1 + nb_packed_inputs;
            pb.set_input_sizes(nb_inputs);
            // ---------------------------------------------------------------
            // //
            // Initialize the digest_variables
            phi.reset(new libsnark::digest_variable<FieldT>(
                pb, 256, FMT(this->annotation_prefix, " phi")));
            h_sig.reset(new libsnark::digest_variable<FieldT>(
                pb, 256, FMT(this->annotation_prefix, " h_sig")));
            for (size_t i = 0; i < NumInputs; i++) {
                input_nullifiers[i].reset(new libsnark::digest_variable<FieldT>(
                    pb,
                    HashT::get_digest_len(),
                    FMT(this->annotation_prefix, " input_nullifiers[%zu]", i)));
                a_sks[i].reset(new libsnark::digest_variable<FieldT>(
                    pb, 256, FMT(this->annotation_prefix, " a_sks[%zu]", i)));
                h_is[i].reset(new libsnark::digest_variable<FieldT>(
                    pb, 256, FMT(this->annotation_prefix, " h_is[%zu]", i)));
            }
            for (size_t i = 0; i < NumOutputs; i++) {
                rho_is[i].reset(new libsnark::digest_variable<FieldT>(
                    pb, 256, FMT(this->annotation_prefix, " rho_is[%zu]", i)));
                output_commitments[i].reset(
                    new libsnark::digest_variable<FieldT>(
                        pb,
                        HashT::get_digest_len(),
                        FMT(this->annotation_prefix,
                            " output_commitments[%zu]",
                            i)));
            }

            // Allocate the zk_vpub_in and zk_vpub_out
            zk_vpub_in.allocate(
                pb, 64, FMT(this->annotation_prefix, " zk_vpub_in"));
            zk_vpub_out.allocate(
                pb, 64, FMT(this->annotation_prefix, " zk_vpub_out"));

            // Initialize the unpacked input corresponding to the input
            // NullifierS
            for (size_t i = 0; i < NumInputs; i++) {
                unpacked_inputs[i].insert(
                    unpacked_inputs[i].end(),
                    input_nullifiers[i]->bits.begin(),
                    input_nullifiers[i]->bits.begin() + FieldT::capacity());
            }

            // Initialize the unpacked input corresponding to the output
            // CommitmentS
            for (size_t i = NumInputs, j = 0;
                 i < NumOutputs + NumInputs && j < NumOutputs;
                 i++, j++) {
                unpacked_inputs[i].insert(
                    unpacked_inputs[i].end(),
                    output_commitments[j]->bits.begin(),
                    output_commitments[j]->bits.begin() + FieldT::capacity());
            }

            // Initialize the unpacked input corresponding to the h_sig
            unpacked_inputs[NumOutputs + NumInputs].insert(
                unpacked_inputs[NumOutputs + NumInputs + 1 + 1].end(),
                h_sig->bits.begin(),
                h_sig->bits.begin() + FieldT::capacity());

            // Initialize the unpacked input corresponding to the h_is
            for (size_t i = NumOutputs + NumInputs + 1, j = 0;
                 i < NumOutputs + NumInputs + 1 + NumInputs && j < NumInputs;
                 i++, j++) {
                unpacked_inputs[i].insert(
                    unpacked_inputs[i].end(),
                    h_is[j]->bits.begin(),
                    h_is[j]->bits.begin() + FieldT::capacity());
            }

            // Initialize the unpacked input corresponding to the variables of
            // size different to 253 bits (smaller inputs and residual bits).
            // We obtain an unpacked value equal to v_in || v_out || h_sig ||
            // nf_{1..NumInputs} || cm_{1..NumOutputs} || h_i_{1..NumInput}.
            // We fill them here in reverse order because of  the use of
            // .insert() function which adds a variable before a given position
            {
                // Filling with the residual bits of the h_is
                for (size_t i = 0; i < NumInputs; i++) {
                    unpacked_inputs[NumOutputs + NumInputs + 1 + NumInputs]
                        .insert(
                            unpacked_inputs
                                [NumOutputs + NumInputs + 1 + NumInputs]
                                    .end(),
                            h_is[NumInputs - i - 1]->bits.begin() +
                                FieldT::capacity(),
                            h_is[NumInputs - i - 1]->bits.end());
                }

                // Filling with the residual bits of the output CommitmentS
                for (size_t i = 0; i < NumOutputs; i++) {
                    unpacked_inputs[NumOutputs + NumInputs + 1 + NumInputs]
                        .insert(
                            unpacked_inputs
                                [NumOutputs + NumInputs + 1 + NumInputs]
                                    .end(),
                            output_commitments[NumOutputs - i - 1]
                                    ->bits.begin() +
                                FieldT::capacity(),
                            output_commitments[NumOutputs - i - 1]->bits.end());
                }

                // Filling with the residual bits of the input NullifierS
                for (size_t i = 0; i < NumInputs; i++) {
                    unpacked_inputs[NumOutputs + NumInputs + 1 + NumInputs]
                        .insert(
                            unpacked_inputs
                                [NumOutputs + NumInputs + 1 + NumInputs]
                                    .end(),
                            input_nullifiers[NumInputs - i - 1]->bits.begin() +
                                FieldT::capacity(),
                            input_nullifiers[NumInputs - i - 1]->bits.end());
                }

                // Filling with the residual bits of the h_sig
                unpacked_inputs[NumOutputs + NumInputs + 1 + NumInputs].insert(
                    unpacked_inputs[NumOutputs + NumInputs + 1 + NumInputs]
                        .end(),
                    h_sig->bits.begin() + FieldT::capacity(),
                    h_sig->bits.end());

                // Filling with the vpub_out (public value taken out of the mix)
                unpacked_inputs[NumOutputs + NumInputs + 1 + NumInputs].insert(
                    unpacked_inputs[NumOutputs + NumInputs + 1 + NumInputs]
                        .end(),
                    zk_vpub_out.begin(),
                    zk_vpub_out.end());

                // Filling with the vpub_in (public value added to the mix)
                unpacked_inputs[NumOutputs + NumInputs + 1 + NumInputs].insert(
                    unpacked_inputs[NumOutputs + NumInputs + 1 + NumInputs]
                        .end(),
                    zk_vpub_in.begin(),
                    zk_vpub_in.end());
            }

            // [SANITY CHECK]
            // The root is a FieldT, hence is not packed
            // The size of the packed inputs should be NumInputs + NumOutputs +
            // 1 + 1 since we are packing all the inputs nullifiers + all the
            // output commitments
            // + the two public values v_pub_in and v_pub_out + the h_sig + the
            // h_iS.
            assert(
                packed_inputs.size() ==
                NumInputs + NumOutputs + 1 + NumInputs + 1);
            assert(nb_packed_inputs == [this]() {
                size_t sum = 0;
                for (const auto &i : packed_inputs) {
                    sum = sum + i.size();
                }
                return sum;
            }());
            assert(nb_inputs == get_inputs_field_element_size());

            // [SANITY CHECK] Total size of unpacked inputs
            size_t total_size_unpacked_inputs = 0;
            for (size_t i = 0; i < NumInputs + NumOutputs + 1 + NumInputs + 1;
                 i++) {
                total_size_unpacked_inputs += unpacked_inputs[i].size();
            }
            assert(
                total_size_unpacked_inputs == get_unpacked_inputs_bit_size());

            // These gadgets will ensure that all of the inputs we provide are
            // boolean constrained, and and correctly packed into field elements
            // We basically build the public inputs here
            //
            // 1. Pack the nullifiers
            for (size_t i = 0; i < NumInputs; i++) {
                packers[i].reset(new libsnark::multipacking_gadget<FieldT>(
                    pb,
                    unpacked_inputs[i],
                    packed_inputs[i],
                    FieldT::capacity(),
                    FMT(this->annotation_prefix,
                        " packer_nullifiers[%zu]",
                        i)));
            }

            // 2. Pack the output commitments
            for (size_t i = NumInputs; i < NumOutputs + NumInputs; i++) {
                packers[i].reset(new libsnark::multipacking_gadget<FieldT>(
                    pb,
                    unpacked_inputs[i],
                    packed_inputs[i],
                    FieldT::capacity(),
                    FMT(this->annotation_prefix,
                        " packer_output_commitments[%zu]",
                        i)));
            }

            // 3. Pack the h_sig
            packers[NumInputs + NumOutputs].reset(
                new libsnark::multipacking_gadget<FieldT>(
                    pb,
                    unpacked_inputs[NumInputs + NumOutputs],
                    packed_inputs[NumInputs + NumOutputs],
                    FieldT::capacity(),
                    FMT(this->annotation_prefix, " packer_h_sig")));

            // 4. Pack the h_iS
            for (size_t i = NumInputs + NumOutputs + 1;
                 i < NumInputs + NumOutputs + 1 + NumInputs;
                 i++) {
                packers[i].reset(new libsnark::multipacking_gadget<FieldT>(
                    pb,
                    unpacked_inputs[i],
                    packed_inputs[i],
                    FieldT::capacity(),
                    FMT(this->annotation_prefix, " packer_h_i[%zu]", i)));
            }

            // 5. Pack the other values and residual bits
            packers[NumInputs + NumOutputs + 1 + NumInputs].reset(
                new libsnark::multipacking_gadget<FieldT>(
                    pb,
                    unpacked_inputs[NumInputs + NumOutputs + 1 + NumInputs],
                    packed_inputs[NumInputs + NumOutputs + 1 + NumInputs],
                    FieldT::capacity(),
                    FMT(this->annotation_prefix, " packer_bits")));

        } // End of the block dedicated to generate the verifier inputs

        ZERO.allocate(pb, FMT(this->annotation_prefix, " ZERO"));
        zk_total_uint64.allocate(
            pb, 64, FMT(this->annotation_prefix, " zk_total"));

        // Input note gadgets for commitments, nullifiers, and spend authority
        // as well as PRF gadgets for the h_iS
        for (size_t i = 0; i < NumInputs; i++) {
            input_notes[i].reset(
                new input_note_gadget<FieldT, HashT, HashTreeT>(
                    pb, ZERO, a_sks[i], input_nullifiers[i], *merkle_root));

            h_i_gadgets[i].reset(new PRF_pk_gadget<FieldT, HashT>(
                pb, ZERO, a_sks[i]->bits, h_sig->bits, i, h_is[i]));
        }

        // Ouput note gadgets for commitments as well as PRF gadgets for the
        // rho_is
        for (size_t i = 0; i < NumOutputs; i++) {
            rho_i_gadgets[i].reset(new PRF_rho_gadget<FieldT, HashT>(
                pb, ZERO, phi->bits, h_sig->bits, i, rho_is[i]));

            output_notes[i].reset(new output_note_gadget<FieldT, HashT>(
                pb, ZERO, rho_is[i], output_commitments[i]));
        }
    }

    void generate_r1cs_constraints()
    {
        // The `true` passed to `generate_r1cs_constraints` ensures that all
        // inputs are boolean strings
        for (size_t i = 0; i < packers.size(); i++) {
            packers[i]->generate_r1cs_constraints(true);
        }

        // Constrain the not-packed digest variables, ensure there are 256 bit
        // long boolean arrays
        phi->generate_r1cs_constraints();
        for (size_t i = 0; i < NumInputs; i++) {
            a_sks[i]->generate_r1cs_constraints();
        }

        // Constrain `ZERO`: Make sure that the ZERO variable is the zero of the
        // field
        libsnark::generate_r1cs_equals_const_constraint<FieldT>(
            this->pb,
            ZERO,
            FieldT::zero(),
            FMT(this->annotation_prefix, " ZERO"));

        // Constrain the JoinSplit inputs and the h_iS
        for (size_t i = 0; i < NumInputs; i++) {
            input_notes[i]->generate_r1cs_constraints();
            h_i_gadgets[i]->generate_r1cs_constraints();
        }

        // Constrain the JoinSplit outputs and the output rho_iS
        for (size_t i = 0; i < NumOutputs; i++) {
            rho_i_gadgets[i]->generate_r1cs_constraints();
            output_notes[i]->generate_r1cs_constraints();
        }

        // Generate the constraints to ensure that the condition of the
        // joinsplit holds (ie: LHS = RHS)
        {
            // Compute the LHS
            libsnark::linear_combination<FieldT> left_side =
                packed_addition(zk_vpub_in);
            for (size_t i = 0; i < NumInputs; i++) {
                left_side = left_side + packed_addition(input_notes[i]->value);
            }

            // Compute the RHS
            libsnark::linear_combination<FieldT> right_side =
                packed_addition(zk_vpub_out);
            for (size_t i = 0; i < NumOutputs; i++) {
                right_side =
                    right_side + packed_addition(output_notes[i]->value);
            }

            // Ensure that both sides are equal (ie: 1 * left_side = right_side)
            this->pb.add_r1cs_constraint(
                libsnark::r1cs_constraint<FieldT>(1, left_side, right_side),
                FMT(this->annotation_prefix, " lhs_rhs_equality_constraint"));

            // See: https://github.com/zcash/zcash/issues/854
            // Ensure that `left_side` is a 64-bit integer
            for (size_t i = 0; i < 64; i++) {
                libsnark::generate_boolean_r1cs_constraint<FieldT>(
                    this->pb,
                    zk_total_uint64[i],
                    FMT(this->annotation_prefix, " zk_total_uint64[%zu]", i));
            }

            this->pb.add_r1cs_constraint(
                libsnark::r1cs_constraint<FieldT>(
                    1, left_side, packed_addition(zk_total_uint64)),
                FMT(this->annotation_prefix, " lhs_equal_zk_total_constraint"));
        }
    }

    void generate_r1cs_witness(
        const FieldT &rt,
        const std::array<JSInput<FieldT>, NumInputs> &inputs,
        const std::array<ZethNote, NumOutputs> &outputs,
        bits64 vpub_in,
        bits64 vpub_out,
        const bits256 h_sig_in,
        const bits256 phi_in)
    {
        // Witness `zero`
        this->pb.val(ZERO) = FieldT::zero();

        // Witness the merkle root
        this->pb.val(*merkle_root) = rt;

        // Witness public values
        //
        // Witness LHS public value
        zk_vpub_in.fill_with_bits(this->pb, get_vector_from_bits64(vpub_in));

        // Witness RHS public value
        zk_vpub_out.fill_with_bits(this->pb, get_vector_from_bits64(vpub_out));

        // Witness h_sig
        h_sig->generate_r1cs_witness(
            libff::bit_vector(get_vector_from_bits256(h_sig_in)));

        // Witness the h_iS, a_sk and rho_iS
        for (size_t i = 0; i < NumInputs; i++) {
            a_sks[i]->generate_r1cs_witness(libff::bit_vector(
                get_vector_from_bits256(inputs[i].spending_key_a_sk)));
        }

        // Witness phi
        phi->generate_r1cs_witness(
            libff::bit_vector(get_vector_from_bits256(phi_in)));

        {
            // Witness total_uint64 bits
            // We add binary numbers here
            // see:
            // https://stackoverflow.com/questions/13282825/adding-binary-numbers-in-c
            bits64 left_side_acc = vpub_in;
            for (size_t i = 0; i < NumInputs; i++) {
                left_side_acc =
                    binary_addition<64>(left_side_acc, inputs[i].note.value());
            }

            zk_total_uint64.fill_with_bits(
                this->pb, get_vector_from_bits64(left_side_acc));
        }

        // Witness the JoinSplit inputs and the h_is
        for (size_t i = 0; i < NumInputs; i++) {
            std::vector<FieldT> merkle_path = inputs[i].witness_merkle_path;
            libff::bit_vector address_bits =
                get_vector_from_bitsAddr(inputs[i].address_bits);
            input_notes[i]->generate_r1cs_witness(
                merkle_path, address_bits, inputs[i].note);

            h_i_gadgets[i]->generate_r1cs_witness();
        }

        // Witness the JoinSplit outputs
        for (size_t i = 0; i < NumOutputs; i++) {
            rho_i_gadgets[i]->generate_r1cs_witness();
            output_notes[i]->generate_r1cs_witness(outputs[i]);
        }

        // This happens last, because only by now are all the
        // verifier inputs resolved.
        for (size_t i = 0; i < packers.size(); i++) {
            packers[i]->generate_r1cs_witness_from_bits();
        }
    }

    // Computes the total bit-length of the primary inputs
    static size_t get_inputs_bit_size()
    {
        size_t acc = 0;

        // Bit-length of the Merkle Root
        acc += FieldT::capacity();

        // Bit-length of the NullifierS
        for (size_t i = 0; i < NumInputs; i++) {
            acc += HashT::get_digest_len();
        }

        // Bit-length of the CommitmentS
        for (size_t i = 0; i < NumOutputs; i++) {
            acc += HashT::get_digest_len();
        }

        // Bit-length of vpub_in
        acc += 64;

        // Bit-length of vpub_out
        acc += 64;

        // Bit-length of h_sig
        acc += 256;

        // Bit-length of the h_iS
        for (size_t i = 0; i < NumInputs; i++) {
            acc += 256;
        }

        return acc;
    }

    // Computes the total bit-length of the unpacked primary inputs
    static size_t get_unpacked_inputs_bit_size()
    {
        // The Merkle root is not in the `unpacked_inputs` so we subtract its
        // bit-length to get the total bit-length of the primary inputs in
        // `unpacked_inputs`
        return get_inputs_bit_size() - FieldT::capacity();
    }

    // Computes the number of field elements in the primary inputs
    static size_t get_inputs_field_element_size()
    {
        size_t nb_elements = 0;

        // The merkle root is represented by 1 field element (bit_length(root) =
        // FieldT::capacity())
        nb_elements += 1;

        // Each nullifier is represented by 1 field element and
        // (HashT::get_digest_len() - FieldT::capacity()) bits we aggregate in
        // the residual field element(s) later on (c.f. last incrementation)
        for (size_t i = 0; i < NumInputs; i++) {
            nb_elements += 1;
        }

        // Each commitment is represented by 1 field element and
        // (HashT::get_digest_len() - FieldT::capacity()) bits we aggregate in
        // the residual field element(s) later on (c.f. last incrementation)
        for (size_t i = 0; i < NumOutputs; i++) {
            nb_elements += 1;
        }

        // The h_sig is represented 1 field element and (HashT::get_digest_len()
        // - FieldT::capacity()) bits we aggregate in the residual field
        // element(s) later on (c.f. last incrementation)
        nb_elements += 1;

        // Each non-mal. tag is represented by 1 field element and
        // (HashT::get_digest_len() - FieldT::capacity()) bits we aggregate in
        // the residual field element(s) later on (c.f. last incrementation)
        for (size_t i = 0; i < NumInputs; i++) {
            nb_elements += 1;
        }

        // Residual bits and public values (in and out) aggregated in
        // `nb_field_residual` field elements
        nb_elements += libff::div_ceil(
            2 * 64 + (HashT::get_digest_len() - FieldT::capacity()) *
                         (1 + 2 * NumInputs + NumOutputs),
            FieldT::capacity());

        return nb_elements;
    }
};

#endif // __ZETH_CIRCUITS_JOINSPLIT_TCC__
