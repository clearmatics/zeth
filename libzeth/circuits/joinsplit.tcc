// Copyright (c) 2015-2021 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_CIRCUITS_JOINSPLIT_TCC__
#define __ZETH_CIRCUITS_JOINSPLIT_TCC__

#include "libzeth/circuits/joinsplit.hpp"

namespace libzeth
{

template<
    typename FieldT,
    typename HashT,
    typename HashTreeT,
    size_t NumInputs,
    size_t NumOutputs,
    size_t TreeDepth>
joinsplit_gadget<FieldT, HashT, HashTreeT, NumInputs, NumOutputs, TreeDepth>::
    joinsplit_gadget(
        libsnark::protoboard<FieldT> &pb, const std::string &annotation_prefix)
    : libsnark::gadget<FieldT>(pb, annotation_prefix)
{
    // Block dedicated to generate the verifier inputs
    {
        // PUBLIC DATA: allocated first so that the protoboard has access.
        //
        // Allocation is currently performed here in the following order
        // (with the protoboard owner determining whether these are primary
        // or auxiliary inputs to the circuit):
        // - Root
        // - NullifierS
        // - CommitmentS
        // - h_sig
        // - h_iS
        // - Residual field element(S)
        //
        // This yields the following index mappings:
        //  0                                 : "Root"
        //  1, ...                            : Nullifiers (NumInputs)
        //  1 + NumInputs, ...                : Commitments (Num Outputs)
        //  1 + NumInputs + NumOutputs        : h_sig
        //  2 + NumInputs + NumOutputs, ...   : h_iS (NumInputs)
        //  2 + 2xNumInputs + NumOutputs, ... : v_in, v_out, residual
        //                                            (nb_field_residual)

        // We first allocate the root
        merkle_root.reset(new libsnark::pb_variable<FieldT>);
        merkle_root->allocate(pb, FMT(this->annotation_prefix, " merkle_root"));

        output_commitments.allocate(pb, NumOutputs, " output_commitments");

        // We allocate a field element for each of the input nullifiers
        // to pack their first FieldT::capacity() bits
        for (size_t i = 0; i < NumInputs; i++) {
            packed_inputs[i].allocate(
                pb, 1, FMT(this->annotation_prefix, " in_nullifier[%zu]", i));
        }

        // We allocate a field element for h_sig to pack its first
        // FieldT::capacity() bits
        packed_inputs[NumInputs].allocate(
            pb, 1, FMT(this->annotation_prefix, " h_sig"));

        // We allocate a field element for each message authentication tags
        // h_iS to pack their first FieldT::capacity() bits
        for (size_t i = NumInputs + 1; i < NumInputs + 1 + NumInputs; i++) {
            packed_inputs[i].allocate(
                pb, 1, FMT(this->annotation_prefix, " h_i[%zu]", i));
        }

        // We allocate as many field elements as needed to pack the public
        // values and the hash digests' residual bits
        packed_inputs[NumInputs + 1 + NumInputs].allocate(
            pb,
            nb_field_residual,
            FMT(this->annotation_prefix, " residual_bits"));

        // Compute the number of packed public elements, and the total
        // number of public elements (see tabel above). The "packed" inputs
        // (those represented as a field elements and some residual bits)
        // are:
        //   H_sig, nullifier, commitments and h_iS
        const size_t num_packed_public_elements =
            2 * NumInputs + 1 + nb_field_residual;
        const size_t num_public_elements =
            1 + NumOutputs + num_packed_public_elements;

        // PRIVATE DATA:

        // Allocate a ZERO variable
        // TODO: check whether/why this is actually needed
        ZERO.allocate(pb, FMT(this->annotation_prefix, " ZERO"));

        // Initialize the digest_variables
        phi.reset(new libsnark::digest_variable<FieldT>(
            pb, ZETH_PHI_SIZE, FMT(this->annotation_prefix, " phi")));
        h_sig.reset(new libsnark::digest_variable<FieldT>(
            pb, ZETH_HSIG_SIZE, FMT(this->annotation_prefix, " h_sig")));
        for (size_t i = 0; i < NumInputs; i++) {
            input_nullifiers[i].reset(new libsnark::digest_variable<FieldT>(
                pb,
                HashT::get_digest_len(),
                FMT(this->annotation_prefix, " input_nullifiers[%zu]", i)));
            a_sks[i].reset(new libsnark::digest_variable<FieldT>(
                pb,
                ZETH_A_SK_SIZE,
                FMT(this->annotation_prefix, " a_sks[%zu]", i)));
            h_is[i].reset(new libsnark::digest_variable<FieldT>(
                pb,
                HashT::get_digest_len(),
                FMT(this->annotation_prefix, " h_is[%zu]", i)));
        }
        for (size_t i = 0; i < NumOutputs; i++) {
            rho_is[i].reset(new libsnark::digest_variable<FieldT>(
                pb,
                HashT::get_digest_len(),
                FMT(this->annotation_prefix, " rho_is[%zu]", i)));
        }

        // Allocate the zk_vpub_in and zk_vpub_out
        zk_vpub_in.allocate(
            pb, ZETH_V_SIZE, FMT(this->annotation_prefix, " zk_vpub_in"));
        zk_vpub_out.allocate(
            pb, ZETH_V_SIZE, FMT(this->annotation_prefix, " zk_vpub_out"));

        // Assign digests to unpacked field elements and residual bits.
        // Note that the order here dictates the layout of residual bits
        // (from lowest order to highest order):
        //
        //   vpub_out,
        //   vpub_in
        //   h_0, ..., h_{num_inputs},
        //   nf_0, ..., nf_{num_inputs},
        //   h_sig,
        //
        // where vpub_out and vpub_in are each 64 bits.
        libsnark::pb_variable_array<FieldT> &residual_bits =
            unpacked_inputs[NumInputs + 1 + NumInputs];

        // Assign the public output and input values to the first residual
        // bits (in this way, they will always appear in the same place in
        // the field element).
        assign_public_value_to_residual_bits(zk_vpub_out, residual_bits);
        assign_public_value_to_residual_bits(zk_vpub_in, residual_bits);

        // Initialize the unpacked input corresponding to the h_is
        for (size_t i = NumInputs + 1, j = 0;
             i < NumInputs + 1 + NumInputs && j < NumInputs;
             i++, j++) {
            digest_variable_assign_to_field_element_and_residual(
                *h_is[j], unpacked_inputs[i], residual_bits);
        }

        // Initialize the unpacked input corresponding to the input
        // NullifierS
        for (size_t i = 0; i < NumInputs; i++) {
            digest_variable_assign_to_field_element_and_residual(
                *input_nullifiers[i], unpacked_inputs[i], residual_bits);
        }

        // Initialize the unpacked input corresponding to the h_sig
        digest_variable_assign_to_field_element_and_residual(
            *h_sig, unpacked_inputs[NumInputs], residual_bits);

        // [SANITY CHECK]
        // The root is a FieldT, hence is not packed, likewise for the cms.
        // The size of the packed inputs should be 2*NumInputs + 1 + 1
        // since we are packing all the inputs nullifiers + the h_is +
        // + the h_sig + the residual bits
        assert(packed_inputs.size() == NumInputs + 1 + NumInputs + 1);
        assert(num_packed_public_elements == [this]() {
            size_t sum = 0;
            for (const auto &i : packed_inputs) {
                sum = sum + i.size();
            }
            return sum;
        }());
        assert(num_public_elements == get_num_public_elements());
        (void)num_public_elements;

        // [SANITY CHECK] Total size of unpacked inputs
        size_t total_size_unpacked_inputs = 0;
        for (size_t i = 0; i < NumInputs + 1 + NumInputs + 1; i++) {
            total_size_unpacked_inputs += unpacked_inputs[i].size();
        }
        assert(total_size_unpacked_inputs == get_unpacked_inputs_bit_size());

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
                FMT(this->annotation_prefix, " packer_nullifiers[%zu]", i)));
        }

        // 2. Pack the h_sig
        packers[NumInputs].reset(new libsnark::multipacking_gadget<FieldT>(
            pb,
            unpacked_inputs[NumInputs],
            packed_inputs[NumInputs],
            FieldT::capacity(),
            FMT(this->annotation_prefix, " packer_h_sig")));

        // 3. Pack the h_iS
        for (size_t i = NumInputs + 1; i < NumInputs + 1 + NumInputs; i++) {
            packers[i].reset(new libsnark::multipacking_gadget<FieldT>(
                pb,
                unpacked_inputs[i],
                packed_inputs[i],
                FieldT::capacity(),
                FMT(this->annotation_prefix, " packer_h_i[%zu]", i)));
        }

        // 4. Pack the other values and residual bits
        packers[NumInputs + 1 + NumInputs].reset(
            new libsnark::multipacking_gadget<FieldT>(
                pb,
                residual_bits,
                packed_inputs[NumInputs + 1 + NumInputs],
                FieldT::capacity(),
                FMT(this->annotation_prefix, " packer_residual_bits")));

    } // End of the block dedicated to generate the verifier inputs

    zk_total_uint64.allocate(
        pb, ZETH_V_SIZE, FMT(this->annotation_prefix, " zk_total"));

    // Input note gadgets for commitments, nullifiers, and spend authority
    // as well as PRF gadgets for the h_iS
    for (size_t i = 0; i < NumInputs; i++) {
        input_notes[i].reset(
            new input_note_gadget<FieldT, HashT, HashTreeT, TreeDepth>(
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
            pb, rho_is[i], output_commitments[i]));
    }
}

template<
    typename FieldT,
    typename HashT,
    typename HashTreeT,
    size_t NumInputs,
    size_t NumOutputs,
    size_t TreeDepth>
void joinsplit_gadget<
    FieldT,
    HashT,
    HashTreeT,
    NumInputs,
    NumOutputs,
    TreeDepth>::generate_r1cs_constraints()
{
    // Check the booleaness of packing variables
    // Check the booleaness of phi and the a_sks
    // Check value of ZERO (i.e. that ZERO = FieldT::zero())
    // Check input notes, output notes, h_iS and rhoS are correctly computed
    // Check the joinsplit is balanced
    // N.B. note_gadget checks the booleaness of v and r_trap
    // N.B. input_note_gadget checks the booleaness of rho^old
    // N.B. output_note_gadget checks the booleaness of of a_pk^new

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
        this->pb, ZERO, FieldT::zero(), FMT(this->annotation_prefix, " ZERO"));

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
            right_side = right_side + packed_addition(output_notes[i]->value);
        }

        // Ensure that both sides are equal (ie: 1 * left_side = right_side)
        this->pb.add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(1, left_side, right_side),
            FMT(this->annotation_prefix, " lhs_rhs_equality_constraint"));

        // See: https://github.com/zcash/zcash/issues/854
        // Ensure that `left_side` is a 64-bit integer
        for (size_t i = 0; i < ZETH_V_SIZE; i++) {
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

template<
    typename FieldT,
    typename HashT,
    typename HashTreeT,
    size_t NumInputs,
    size_t NumOutputs,
    size_t TreeDepth>
void joinsplit_gadget<
    FieldT,
    HashT,
    HashTreeT,
    NumInputs,
    NumOutputs,
    TreeDepth>::
    generate_r1cs_witness(
        const FieldT &rt,
        const std::array<joinsplit_input<FieldT, TreeDepth>, NumInputs> &inputs,
        const std::array<zeth_note, NumOutputs> &outputs,
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
    vpub_in.fill_variable_array(this->pb, zk_vpub_in);

    // Witness RHS public value
    vpub_out.fill_variable_array(this->pb, zk_vpub_out);

    // Witness h_sig
    h_sig->generate_r1cs_witness(h_sig_in.to_vector());

    // Witness the h_iS, a_sk and rho_iS
    for (size_t i = 0; i < NumInputs; i++) {
        a_sks[i]->generate_r1cs_witness(
            inputs[i].spending_key_a_sk.to_vector());
    }

    // Witness phi
    phi->generate_r1cs_witness(phi_in.to_vector());

    {
        // Witness total_uint64 bits
        // We add binary numbers here see:
        // https://stackoverflow.com/questions/13282825/adding-binary-numbers-in-c
        // To check left_side_acc < 2^64, we set the function's bool to true
        bits64 left_side_acc = vpub_in;
        for (size_t i = 0; i < NumInputs; i++) {
            left_side_acc = bits_add<ZETH_V_SIZE>(
                left_side_acc, inputs[i].note.value, true);
        }

        left_side_acc.fill_variable_array(this->pb, zk_total_uint64);
    }

    // Witness the JoinSplit inputs and the h_is
    for (size_t i = 0; i < NumInputs; i++) {
        input_notes[i]->generate_r1cs_witness(
            inputs[i].witness_merkle_path,
            inputs[i].address_bits,
            inputs[i].note);

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

template<
    typename FieldT,
    typename HashT,
    typename HashTreeT,
    size_t NumInputs,
    size_t NumOutputs,
    size_t TreeDepth>
void joinsplit_gadget<
    FieldT,
    HashT,
    HashTreeT,
    NumInputs,
    NumOutputs,
    TreeDepth>::
    digest_variable_assign_to_field_element_and_residual(
        const libsnark::digest_variable<FieldT> &digest_var,
        libsnark::pb_variable_array<FieldT> &unpacked_element,
        libsnark::pb_variable_array<FieldT> &unpacked_residual_bits)
{
    const size_t field_capacity = FieldT::capacity();

    // Digest_var holds bits high-order first. pb_variable_array will be
    // packed with low-order bit first to match the evm.

    // The field element holds the lowest order bits ordered 256 -
    // digest_len_minus_field_cap bits.
    unpacked_element.insert(
        unpacked_element.end(),
        digest_var.bits.rbegin(),
        digest_var.bits.rbegin() + field_capacity);

    // The remaining high order bits are appended to
    // unpacked_residual_bits.
    unpacked_residual_bits.insert(
        unpacked_residual_bits.end(),
        digest_var.bits.rbegin() + field_capacity,
        digest_var.bits.rend());
}

template<
    typename FieldT,
    typename HashT,
    typename HashTreeT,
    size_t NumInputs,
    size_t NumOutputs,
    size_t TreeDepth>
void joinsplit_gadget<
    FieldT,
    HashT,
    HashTreeT,
    NumInputs,
    NumOutputs,
    TreeDepth>::
    assign_public_value_to_residual_bits(
        const libsnark::pb_variable_array<FieldT> &unpacked_public_value,
        libsnark::pb_variable_array<FieldT> &unpacked_residual_bits)
{
    unpacked_residual_bits.insert(
        unpacked_residual_bits.end(),
        unpacked_public_value.rbegin(),
        unpacked_public_value.rend());
}

template<
    typename FieldT,
    typename HashT,
    typename HashTreeT,
    size_t NumInputs,
    size_t NumOutputs,
    size_t TreeDepth>
size_t joinsplit_gadget<
    FieldT,
    HashT,
    HashTreeT,
    NumInputs,
    NumOutputs,
    TreeDepth>::get_inputs_bit_size()
{
    size_t acc = 0;

    // Bit-length of the Merkle Root
    acc += FieldT::capacity();

    // Bit-length of the CommitmentS
    for (size_t i = 0; i < NumOutputs; i++) {
        acc += FieldT::capacity();
    }

    // Bit-length of the NullifierS
    for (size_t i = 0; i < NumInputs; i++) {
        acc += HashT::get_digest_len();
    }

    // Bit-length of vpub_in
    acc += ZETH_V_SIZE;

    // Bit-length of vpub_out
    acc += ZETH_V_SIZE;

    // Bit-length of h_sig
    acc += HashT::get_digest_len();

    // Bit-length of the h_iS
    for (size_t i = 0; i < NumInputs; i++) {
        acc += HashT::get_digest_len();
    }

    return acc;
}

template<
    typename FieldT,
    typename HashT,
    typename HashTreeT,
    size_t NumInputs,
    size_t NumOutputs,
    size_t TreeDepth>
size_t joinsplit_gadget<
    FieldT,
    HashT,
    HashTreeT,
    NumInputs,
    NumOutputs,
    TreeDepth>::get_unpacked_inputs_bit_size()
{
    // The Merkle root and commitments are not in the `unpacked_inputs`
    // so we subtract their bit-length to get the total bit-length of
    // the primary inputs in `unpacked_inputs`
    return get_inputs_bit_size() - (1 + NumOutputs) * FieldT::capacity();
}

template<
    typename FieldT,
    typename HashT,
    typename HashTreeT,
    size_t NumInputs,
    size_t NumOutputs,
    size_t TreeDepth>
size_t joinsplit_gadget<
    FieldT,
    HashT,
    HashTreeT,
    NumInputs,
    NumOutputs,
    TreeDepth>::get_num_public_elements()
{
    size_t nb_elements = 0;

    // The merkle root is represented by 1 field element (bit_length(root) =
    // FieldT::capacity())
    nb_elements += 1;

    // Each commitment is represented by 1 field element (bit_length(cm) =
    // FieldT::capacity())
    for (size_t i = 0; i < NumOutputs; i++) {
        nb_elements += 1;
    }

    // Each nullifier is represented by 1 field element and
    // (HashT::get_digest_len() - FieldT::capacity()) bits we aggregate in
    // the residual field element(s) later on (c.f. last incrementation)
    for (size_t i = 0; i < NumInputs; i++) {
        nb_elements += 1;
    }

    // The h_sig is represented 1 field element and (HashT::get_digest_len()
    // - FieldT::capacity()) bits we aggregate in the residual field
    // element(s) later on (c.f. last incrementation)
    nb_elements += 1;

    // Each authentication tag is represented by 1 field element and
    // (HashT::get_digest_len() - FieldT::capacity()) bits we aggregate in
    // the residual field element(s) later on (c.f. last incrementation)
    for (size_t i = 0; i < NumInputs; i++) {
        nb_elements += 1;
    }

    // Residual bits and public values (in and out) aggregated in
    // `nb_field_residual` field elements
    nb_elements += libff::div_ceil(
        2 * ZETH_V_SIZE +
            subtract_with_clamp(HashT::get_digest_len(), FieldT::capacity()) *
                (1 + 2 * NumInputs),
        FieldT::capacity());

    return nb_elements;
}

} // namespace libzeth

#endif // __ZETH_CIRCUITS_JOINSPLIT_TCC__
